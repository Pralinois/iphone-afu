# lang: Python 3.10+
# file: modules/report_builder.py
# deps: stdlib (json, pathlib, datetime, html)
# pas de Jinja2, pas de dépendance externe — HTML généré par string formatting

"""Rapport HTML standalone (dark theme) depuis un répertoire auto_out/.

Importable :
    from modules.report_builder import build_html_report

Runnable seul :
    python -m modules.report_builder <auto_out_dir> [-o report.html]
"""

import argparse
import html
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

REPORT_SECTIONS = [
    ("device",        "Device Info",          "device.json"),
    ("apps",          "Applications",         "apps.json"),
    ("macho",         "Mach-O Analysis",      "macho_report.json"),
    ("strings_hunt",  "Secrets Found",        "findings.json"),
    ("network",       "Network Surface",      "network_report.json"),
    ("audit",         "Security Audit",       "audit_report.json"),
    ("auto_report",   "Pipeline Summary",     "auto_report.json"),
]

SEVERITY_CLASSES = {"HIGH": "sev-high", "MEDIUM": "sev-med", "LOW": "sev-low",
                    "INFO": "sev-info", "CRITICAL": "sev-high"}

CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;
       background: #0d1117; color: #c9d1d9; }
header { padding: 18px 28px; background: #161b22; border-bottom: 1px solid #30363d;
         position: sticky; top: 0; z-index: 5; }
header h1 { margin: 0 0 4px; font-size: 19px; color: #58a6ff; }
header .meta { font-size: 12px; color: #8b949e; }
.layout { display: flex; }
nav { width: 220px; padding: 18px 12px; border-right: 1px solid #30363d;
      position: sticky; top: 82px; align-self: flex-start; max-height: 90vh;
      overflow-y: auto; }
nav a { display: block; padding: 6px 10px; color: #8b949e; text-decoration: none;
        border-radius: 6px; font-size: 13px; }
nav a:hover { background: #21262d; color: #c9d1d9; }
main { flex: 1; padding: 20px 28px 60px; min-width: 0; }
section { margin-bottom: 34px; }
section h2 { font-size: 16px; color: #58a6ff; border-bottom: 1px solid #30363d;
             padding-bottom: 6px; }
table { border-collapse: collapse; width: 100%; font-size: 12.5px; margin-top: 8px; }
th { text-align: left; background: #161b22; color: #8b949e; padding: 7px 9px;
     border: 1px solid #30363d; position: sticky; top: 82px; }
td { padding: 6px 9px; border: 1px solid #21262d; vertical-align: top;
     word-break: break-word; max-width: 520px; }
tr:nth-child(even) td { background: #11161d; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px;
         font-size: 11px; font-weight: 600; }
.sev-high { background: #f8514922; color: #f85149; border: 1px solid #f85149; }
.sev-med  { background: #d2992222; color: #d29922; border: 1px solid #d29922; }
.sev-low  { background: #8b949e22; color: #8b949e; border: 1px solid #8b949e; }
.sev-info { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff; }
.kv td:first-child { color: #8b949e; width: 220px; }
pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
      padding: 10px; overflow-x: auto; font-size: 12px; }
.empty { color: #8b949e; font-style: italic; font-size: 13px; }
footer { padding: 14px 28px; color: #8b949e; font-size: 11.5px;
         border-top: 1px solid #30363d; }
"""


def _esc(val) -> str:
    return html.escape(str(val))


def _badge(sev: str) -> str:
    sev = str(sev).upper()
    cls = SEVERITY_CLASSES.get(sev, "sev-info")
    return f'<span class="badge {cls}">{_esc(sev)}</span>'


def _render_table(rows: list[dict], columns: Optional[list[str]] = None,
                  badge_keys: tuple = ("severity", "sev")) -> str:
    if not rows:
        return '<p class="empty">(aucune entrée)</p>'
    if columns is None:
        columns = []
        for row in rows:
            for k in row:
                if k not in columns:
                    columns.append(k)
        columns = columns[:10]
    head = "".join(f"<th>{_esc(c)}</th>" for c in columns)
    body = []
    for row in rows:
        cells = []
        for c in columns:
            val = row.get(c, "")
            if c in badge_keys and val:
                cells.append(f"<td>{_badge(val)}</td>")
            elif isinstance(val, (dict, list)):
                cells.append(f"<td><pre>{_esc(json.dumps(val, ensure_ascii=False)[:400])}</pre></td>")
            else:
                cells.append(f"<td>{_esc(str(val)[:500])}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _render_kv(obj: dict) -> str:
    if not obj:
        return '<p class="empty">(vide)</p>'
    rows = "".join(f"<tr><td>{_esc(k)}</td><td>{_esc(str(v)[:300])}</td></tr>"
                   for k, v in obj.items())
    return f'<table class="kv">{rows}</table>'


def _render_generic(data) -> str:
    """Rend un JSON quelconque : liste → table, dict avec findings → badges, dict → kv."""
    if isinstance(data, list):
        return _render_table([d for d in data if isinstance(d, dict)] or
                             [{"value": d} for d in data])
    if isinstance(data, dict):
        for key in ("findings", "results", "entries"):
            inner = data.get(key)
            if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                rest = {k: v for k, v in data.items() if k != key}
                return _render_kv(rest) + _render_table(inner)
        if all(not isinstance(v, (dict, list)) for v in data.values()):
            return _render_kv(data)
        return f"<pre>{_esc(json.dumps(data, indent=1, ensure_ascii=False)[:6000])}</pre>"
    return f"<pre>{_esc(str(data)[:2000])}</pre>"


def build_html_report(auto_out_dir: Path, output_path: Path) -> Path:
    """Génère un rapport HTML standalone depuis les JSON présents dans auto_out_dir."""
    auto_out_dir = Path(auto_out_dir)
    output_path = Path(output_path)
    if not auto_out_dir.is_dir():
        raise RuntimeError(f"répertoire introuvable : {auto_out_dir}")

    device = {}
    device_file = auto_out_dir / "device.json"
    if device_file.exists():
        try:
            device = json.loads(device_file.read_text(encoding="utf-8"))
        except ValueError:
            device = {}

    sections_html: list[str] = []
    nav_html: list[str] = []
    found = 0
    for anchor, title, filename in REPORT_SECTIONS:
        src = auto_out_dir / filename
        if not src.exists():
            continue
        try:
            data = json.loads(src.read_text(encoding="utf-8"))
        except ValueError:
            sections_html.append(
                f'<section id="{anchor}"><h2>{_esc(title)}</h2>'
                f'<p class="empty">JSON illisible : {_esc(filename)}</p></section>')
            nav_html.append(f'<a href="#{anchor}">{_esc(title)}</a>')
            continue
        found += 1
        nav_html.append(f'<a href="#{anchor}">{_esc(title)}</a>')
        sections_html.append(
            f'<section id="{anchor}"><h2>{_esc(title)} '
            f'<span class="meta">({_esc(filename)})</span></h2>{_render_generic(data)}</section>')

    if not found:
        sections_html.append(
            '<section><h2>Aucune donnée</h2><p class="empty">'
            'Aucun JSON reconnu dans ce répertoire — lance d’abord `auto`, `scan` ou `audit`.</p>'
            "</section>")

    device_name = device.get("DeviceName") or device.get("ProductType") or "device inconnu"
    generated = datetime.now().isoformat(timespec="seconds")
    doc = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AFU Report — {_esc(device_name)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>iPhone AFU — Rapport d'analyse</h1>
  <div class="meta">{_esc(device_name)} · {_esc(device.get('ProductVersion', ''))} ·
    généré le {_esc(generated)}</div>
</header>
<div class="layout">
  <nav>{''.join(nav_html) or '<span class="empty">(vide)</span>'}</nav>
  <main>{''.join(sections_html)}</main>
</div>
<footer>iphone-afu · rapport standalone généré localement — aucune ressource externe</footer>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(doc, encoding="utf-8")
    return output_path


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="report_builder",
                                     description="Génère un rapport HTML standalone depuis auto_out/")
    parser.add_argument("source", help="Répertoire de sortie auto")
    parser.add_argument("-o", "--output", default="report.html")
    args = parser.parse_args(argv)
    try:
        out = build_html_report(Path(args.source), Path(args.output))
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1
    print(f"[+] rapport → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
