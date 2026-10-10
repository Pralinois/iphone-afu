# lang: Python 3.10+
# file: modules/network_recon.py
# deps: stdlib (socket, re, json, collections, urllib, concurrent.futures)
# skill refs: recon-and-methodology, traffic-analysis-pcap

"""Surface réseau du device : parse syslog, résolution DNS, GeoIP.

Importable :
    from modules.network_recon import parse_syslog_connections, generate_network_report

Runnable seul :
    python -m modules.network_recon --syslog-parse syslog.txt [--resolve] [--geoip] [-o network_out]
"""

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

SYSLOG_NETWORK_PATTERNS = {
    "tcp_connect":  r"TCP\s+\w+\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s*[<>-]+\s*(\d+\.\d+\.\d+\.\d+):(\d+)",
    "dns_query":    r"dns_query\s+(\S+)\s+type=(\w+)",
    "url":          r"https?://([a-zA-Z0-9.\-]+)(?:/[^\s\"']*)?",
    "domain":       r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "ip_private":   r"\b(?:10(?:\.\d{1,3}){3}|(?:172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)(?:\.\d{1,3}){2})\b",
    "ip_public":    r"\b(?!10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
}

SKIP_DOMAINS = {"apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com", "localhost"}
PRIVATE_RX = re.compile(SYSLOG_NETWORK_PATTERNS["ip_private"])
PUBLIC_RX = re.compile(SYSLOG_NETWORK_PATTERNS["ip_public"])
DOMAIN_RX = re.compile(SYSLOG_NETWORK_PATTERNS["domain"])
TCP_RX = re.compile(SYSLOG_NETWORK_PATTERNS["tcp_connect"])
DNS_RX = re.compile(SYSLOG_NETWORK_PATTERNS["dns_query"])
URL_RX = re.compile(SYSLOG_NETWORK_PATTERNS["url"])

GEOIP_BATCH_URL = "http://ip-api.com/batch"
GEOIP_MAX_PER_CALL = 100


def parse_syslog_connections(syslog_path: Path) -> dict:
    """Parse un syslog iOS → domaines, IPs, URLs, connexions TCP, requêtes DNS."""
    text = Path(syslog_path).read_text(errors="replace")
    domains: Counter = Counter()
    ips: Counter = Counter()
    urls: list[str] = []
    seen_urls: set[str] = set()
    tcp_connections: list[dict] = []
    dns_queries: list[str] = []

    for line in text.splitlines():
        for m in URL_RX.finditer(line):
            host = m.group(1)
            if host not in seen_urls:
                seen_urls.add(host)
                url = m.group(0)
                if url not in urls:
                    urls.append(url)
        for m in DOMAIN_RX.finditer(line):
            dom = m.group(0).lower().rstrip(".")
            if "." in dom and not re.fullmatch(r"[\d.]+", dom):
                domains[dom] += 1
        for m in TCP_RX.finditer(line):
            src, sport, dst, dport = m.groups()
            tcp_connections.append({"src": src, "src_port": int(sport),
                                    "dst": dst, "dst_port": int(dport)})
            ips[src] += 1
            ips[dst] += 1
        for m in DNS_RX.finditer(line):
            dns_queries.append(m.group(1))
        for m in PRIVATE_RX.finditer(line):
            ips[m.group(0)] += 1
        for m in PUBLIC_RX.finditer(line):
            ip = m.group(0)
            if len(ip.split(".")) == 4 and all(0 <= int(o) <= 255 for o in ip.split(".")):
                ips[ip] += 1

    return {
        "domains": domains,
        "ips": ips,
        "urls": urls,
        "tcp_connections": tcp_connections,
        "dns_queries": dns_queries,
    }


def resolve_domains(domains: list[str], timeout: float = 2.0) -> dict:
    """Résolution DNS parallèle → {domain: ip|NXDOMAIN|TIMEOUT|ERREUR}."""
    results: dict = {}

    def one(dom: str) -> tuple[str, str]:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return dom, socket.gethostbyname(dom)
        except socket.gaierror:
            return dom, "NXDOMAIN"
        except (socket.timeout, TimeoutError):
            return dom, "TIMEOUT"
        except OSError:
            return dom, "ERREUR"
        finally:
            socket.setdefaulttimeout(old)

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(one, d): d for d in domains}
        for fut in as_completed(futures):
            try:
                dom, ip = fut.result()
                results[dom] = ip
            except Exception:
                results[futures[fut]] = "ERREUR"
    return results


def geoip_lookup(ips: list[str]) -> dict:
    """Lookup GeoIP via ip-api.com (batch ≤ 100). Retourne {ip: {country, org, asn}}."""
    if not GEOIP_BATCH_URL.startswith(("http://", "https://")):
        raise RuntimeError(f"URL GeoIP invalide : {GEOIP_BATCH_URL}")
    out: dict = {}
    public = [ip for ip in ips if not PRIVATE_RX.search(ip)]
    for i in range(0, len(public), GEOIP_MAX_PER_CALL):
        chunk = public[i:i + GEOIP_MAX_PER_CALL]
        body = json.dumps([{"query": ip, "fields": "status,country,org,as,query"}
                           for ip in chunk]).encode()
        req = urllib.request.Request(GEOIP_BATCH_URL, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 — URL constante https validée ci-dessus
                payload = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, ValueError):
            continue
        for entry in payload if isinstance(payload, list) else []:
            if entry.get("status") == "success":
                out[entry["query"]] = {
                    "country": entry.get("country"),
                    "org": entry.get("org"),
                    "asn": entry.get("as"),
                }
    return out


def default_exts_note() -> str:
    return "extensions: aucun filtre — report de surface"


def generate_network_report(connections: dict, resolved: dict, geo: dict,
                            output_dir: Path) -> dict:
    """Écrit network_report.json + network_domains.txt. Retourne le résumé."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    domains = connections["domains"]
    ips = connections["ips"]

    interesting = sorted(
        (d for d in domains if not any(d.endswith(skip) for skip in SKIP_DOMAINS)),
        key=lambda d: domains[d], reverse=True)

    report = {
        "total_domains": len(domains),
        "total_ips": len(ips),
        "unique_countries": len({g["country"] for g in geo.values() if g.get("country")}),
        "top_5_domains": [[d, domains[d]] for d in interesting[:5]],
        "domains": dict(domains.most_common()),
        "ips": dict(ips.most_common()),
        "urls": connections["urls"],
        "tcp_connections": connections["tcp_connections"][:2000],
        "dns_queries": sorted(set(connections["dns_queries"]))[:2000],
        "resolved": resolved,
        "geoip": geo,
    }
    (output_dir / "network_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (output_dir / "network_domains.txt").write_text(
        "\n".join(interesting) + "\n", encoding="utf-8")
    return {
        "total_domains": report["total_domains"],
        "total_ips": report["total_ips"],
        "unique_countries": report["unique_countries"],
        "top_5_domains": report["top_5_domains"],
        "report": str(output_dir / "network_report.json"),
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="network_recon",
                                     description="Surface réseau — syslog + DNS + GeoIP")
    parser.add_argument("--syslog-parse", dest="syslog_file", help="Fichier syslog à parser")
    parser.add_argument("--resolve", action="store_true", help="Résoudre les domaines en DNS")
    parser.add_argument("--geoip", action="store_true", help="Lookup GeoIP (ip-api.com)")
    parser.add_argument("-o", "--output", default="./network_out")
    parser.add_argument("--top", type=int, default=30, help="Afficher les N top domaines")
    args = parser.parse_args(argv)

    if not args.syslog_file:
        parser.print_help()
        return 1
    src = Path(args.syslog_file)
    if not src.is_file():
        print(f"[!] syslog introuvable : {src}")
        return 1

    connections = parse_syslog_connections(src)
    resolved = resolve_domains(list(connections["domains"])) if args.resolve else {}
    geo = geoip_lookup(list(connections["ips"])) if args.geoip else {}
    summary = generate_network_report(connections, resolved, geo, Path(args.output))

    print(f"[*] {summary['total_domains']} domaines, {summary['total_ips']} IPs")
    for dom, count in summary["top_5_domains"]:
        print(f"  {count:5d}  {dom}")
    print(f"[+] rapport → {summary['report']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
