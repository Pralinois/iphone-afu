# lang: Python 3.10+
# file: modules/proxy_setup.py
# deps: mitmproxy>=10.0 (optionnel), stdlib socket/plistlib
# skill refs: traffic-analysis-pcap, mobile-ssl-pinning-bypass

"""Setup MITM proxy iOS : IP host, cert CA, mobileconfig, mitmdump, bypass pinning Frida.

Importable :
    from modules.proxy_setup import (get_host_ip, generate_mitmproxy_cert,
                                     install_cert_on_device, start_mitmproxy,
                                     generate_frida_pinning_bypass, print_proxy_instructions)

Runnable seul :
    python -m modules.proxy_setup [--port 8080] [--write-bypass bypass.js]
"""

import argparse
import plistlib
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

DEFAULT_CERT_DIR = Path.home() / ".mitmproxy"

FRIDA_BYPASS_SCRIPT = '''
/* SSL Pinning Bypass — iOS AFU Tool v2
   skill ref: mobile-ssl-pinning-bypass
   covers: Security.framework hooks + common networking libs */

"use strict";

// 1. SecTrustEvaluate — legacy, iOS < 15
var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
if (SecTrustEvaluate) {
    Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
        if (result) Memory.writeU32(result, 1); // kSecTrustResultUnspecified
        return 0; // errSecSuccess
    }, "int", ["pointer", "pointer"]));
}

// 2. SecTrustEvaluateWithError — iOS 15+
var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
if (SecTrustEvaluateWithError) {
    Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
        if (error) Memory.writePointer(error, NULL);
        return 1; // true = trusted
    }, "bool", ["pointer", "pointer"]));
}

// 3. NSURLSession — pinning via delegate
var NSURLCredential = ObjC.classes.NSURLCredential;
if (NSURLCredential) {
    var credMethod = NSURLCredential["+ credentialForTrust:"];
    if (credMethod) {
        Interceptor.attach(credMethod.implementation, {
            onLeave: function(retval) { /* keep credential, bypass check */ }
        });
    }
}

// 4. TrustKit — if present
try {
    var TSKPinningValidator = ObjC.classes.TSKPinningValidator;
    if (TSKPinningValidator) {
        var evaluateMethod = TSKPinningValidator["- evaluateTrust:forHostname:"];
        if (evaluateMethod) {
            Interceptor.attach(evaluateMethod.implementation, {
                onLeave: function(retval) { retval.replace(0); } // TSKTrustEvaluationSuccess
            });
        }
    }
} catch(e) {}

// 5. Alamofire ServerTrustManager (Swift)
// Hook via ObjC bridge or mangled symbol if present
try {
    var mods = Process.enumerateModulesSync();
    mods.forEach(function(m) {
        if (m.name.indexOf("Alamofire") !== -1) {
            // Symbol: $s9Alamofire26ServerTrustPolicyManagerC8evaluateXXXX
            // Hook at module level — name varies per version, scan exports
            var exp = Module.enumerateExportsSync(m.name);
            exp.forEach(function(e) {
                if (e.name.indexOf("ServerTrust") !== -1 && e.name.indexOf("evaluate") !== -1) {
                    Interceptor.attach(e.address, { onLeave: function(r) { r.replace(ptr(1)); } });
                }
            });
        }
    });
} catch(e) {}

console.log("[AFU] SSL pinning bypass active — " + new Date().toISOString());
'''


def get_host_ip() -> str:
    """IP LAN de la machine host (interface non-loopback active)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def generate_mitmproxy_cert(cert_dir: Path = DEFAULT_CERT_DIR) -> Path:
    """Génère/réutilise le CA mitmproxy (mitmproxy-ca-cert.pem). Retourne le PEM."""
    cert_dir = Path(cert_dir)
    pem = cert_dir / "mitmproxy-ca-cert.pem"
    if pem.exists():
        return pem
    cert_dir.mkdir(parents=True, exist_ok=True)
    try:
        from mitmproxy import certs
        certs.CertStore.from_store(str(cert_dir), "mitmproxy", key_size=2048)
    except ImportError as e:
        raise RuntimeError(
            "mitmproxy non installé (pip install mitmproxy) — ou lance `mitmdump` une fois "
            "pour générer ~/.mitmproxy/mitmproxy-ca-cert.pem"
        ) from e
    except Exception as e:
        raise RuntimeError(f"génération du CA mitmproxy échouée : {e}") from e
    if not pem.exists():
        raise RuntimeError(f"CA non générée dans {cert_dir} — lance `mitmdump` une fois")
    return pem


def build_mobileconfig(cert_pem: Path, display_name: str = "AFU MITM CA") -> bytes:
    """Profil .mobileconfig avec payload com.apple.security.root (CA racine)."""
    pem_bytes = Path(cert_pem).read_bytes()
    payload = {
        "PayloadType": "com.apple.security.root",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.afu.mitm.{uuid.uuid4().hex[:12]}",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": display_name,
        "PayloadContent": pem_bytes,
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML)


def install_cert_on_device(lockdown, cert_pem: Path,
                           profile_out: Optional[Path] = None) -> bool:
    """
    Installe le CA sur le device via MDM profile (MCInstall) si la version le permet.
    Sinon : écrit le .mobileconfig pour installation manuelle (AirDrop/Settings).
    """
    profile = build_mobileconfig(cert_pem)
    profile_out = Path(profile_out) if profile_out else Path(cert_pem).parent / "afu-mitm.mobileconfig"
    profile_out.write_bytes(profile)

    candidates = []
    try:
        from pymobiledevice3.services.mobile_config import MobileConfigService
        candidates.append(MobileConfigService)
    except ImportError:
        pass
    try:
        from pymobiledevice3.services.mc_install import MCInstallService
        candidates.append(MCInstallService)
    except ImportError:
        pass

    for svc_cls in candidates:
        try:
            svc = svc_cls(lockdown)
            for method in ("install_profile", "install", "install_profile_from_path"):
                fn = getattr(svc, method, None)
                if fn is None:
                    continue
                try:
                    fn(profile)
                    return True
                except TypeError:
                    fn(str(profile_out))
                    return True
        except Exception:
            continue
    return False


def start_mitmproxy(port: int, pcap_out: Optional[Path] = None,
                    addon_script: Optional[Path] = None) -> subprocess.Popen:
    """Lance mitmdump en arrière-plan (stream pcap optionnel). Retourne le Popen."""
    binary = shutil.which("mitmdump")
    if binary:
        cmd = [binary, "-p", str(port)]
    else:
        try:
            import mitmproxy  # noqa: F401
        except ImportError as e:
            raise RuntimeError("mitmproxy non installé — pip install mitmproxy") from e
        cmd = [sys.executable, "-m", "mitmproxy.tools.dump", "-p", str(port)]

    if pcap_out:
        cmd += ["--save-stream-file", str(pcap_out)]
    if addon_script:
        cmd += ["-s", str(addon_script)]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    time.sleep(1.5)
    if proc.poll() is not None:
        err = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"mitmdump mort au démarrage : {err[:200]}")
    return proc


def generate_frida_pinning_bypass(output_path: Path) -> Path:
    """Écrit le script Frida de bypass SSL pinning complet. Retourne le path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(FRIDA_BYPASS_SCRIPT, encoding="utf-8")
    return output_path


def inject_frida_script(bundle_id: str, script_path: Path, timeout: int = 30) -> dict:
    """Injecte un script Frida via le CLI (frida -U -f <bundle> -l <script>)."""
    try:
        proc = subprocess.run(
            ["frida", "-U", "--no-pause", "-f", bundle_id, "-l", str(script_path)],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "injected", "error": f"frida actif > {timeout}s (hooks en place)"}
    except FileNotFoundError:
        return {"status": "error", "error": "frida non installé — pip install frida-tools"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    if proc.returncode == 0:
        return {"status": "success", "error": None}
    return {"status": "error", "error": (proc.stderr or proc.stdout or "")[:400]}


def print_proxy_instructions(host_ip: str, port: int, cert_installed: bool) -> str:
    """Instructions de configuration proxy sur l'iPhone (retourne le texte, imprime si CLI)."""
    lines = [
        "Configuration proxy sur l'iPhone :",
        "  1. Réglages → Wi-Fi → (réseau) → Configurer le proxy → Manuel",
        f"  2. Serveur : {host_ip}   Port : {port}",
        "  3. SAUVEGARDER",
        "",
        "Certificat CA :",
        f"  - installé via MDM : {'oui' if cert_installed else 'non'}",
        "  - manuel : AirDrop le .mobileconfig sur l'iPhone → Réglages → Profil téléchargé → Installer",
        "  - puis : Réglages → Général → Informations → Réglages de confiance des certificats → activer",
        f"  - cert PEM : {DEFAULT_CERT_DIR / 'mitmproxy-ca-cert.pem'}",
        "",
        "Bypass SSL pinning (device re-signé ou jailbreaké) :",
        "  frida -U -f <bundle_id> -l afu_bypass_pinning.js",
    ]
    text = "\n".join(lines)
    print(text)
    return text


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="proxy_setup",
                                     description="Setup MITM proxy iOS + bypass SSL pinning")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--output", help="Fichier de capture .pcap")
    parser.add_argument("--script", help="Script mitmproxy addon Python")
    parser.add_argument("--write-bypass", help="Écrit le script Frida de bypass puis quitte")
    args = parser.parse_args(argv)

    if args.write_bypass:
        out = generate_frida_pinning_bypass(Path(args.write_bypass))
        print(f"[+] script Frida → {out}")
        return 0

    host_ip = get_host_ip()
    print(f"[*] IP host : {host_ip}")
    proc = start_mitmproxy(args.port, Path(args.output) if args.output else None,
                           Path(args.script) if args.script else None)
    print(f"[+] mitmdump actif (pid={proc.pid}, port={args.port})")
    print_proxy_instructions(host_ip, args.port, cert_installed=False)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
