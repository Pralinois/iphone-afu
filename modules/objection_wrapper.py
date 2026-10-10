# lang: Python 3.10+
# file: modules/objection_wrapper.py
# deps: objection (pip install objection), frida-tools
# skill refs: ios-pentesting-tricks §5, anti-debugging-techniques

"""Wrapper Objection : presets de recon runtime iOS + batch + REPL.

Importable :
    from modules.objection_wrapper import run_objection_preset, batch_recon

Runnable seul :
    python -m modules.objection_wrapper -b com.target.app [--cmd cookies --batch]
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Presets tirés du skill ios-pentesting-tricks §5
OBJECTION_PRESETS = {
    "pasteboard":   "ios pasteboard monitor",
    "cookies":      "ios cookies get",
    "jailbreak":    "ios jailbreak disable",
    "prefs":        "ios nsuserdefaults get",
    "keychain":     "ios keychain dump",
    "ssl":          "ios sslpinning disable",
    "classes":      "ios hooking list classes",
    "methods":      "ios hooking search methods",   # + pattern arg
    "dump-args":    "ios hooking list class_methods",
    "env":          "env",
    "files":        "ios bundles list_bundles",
}

DEFAULT_TIMEOUT = 120


def check_objection() -> bool:
    """True si le binaire objection est disponible."""
    return shutil.which("objection") is not None


def _build_cmd(bundle_id: str, command: str) -> list[str]:
    return ["objection", "-g", bundle_id, "explore", "--startup-command", command]


def run_objection_preset(bundle_id: str, preset: str, extra_arg: Optional[str] = None,
                         output_path: Optional[Path] = None,
                         timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Lance `objection explore --startup-command <preset>` et retourne le résultat."""
    if preset not in OBJECTION_PRESETS:
        return {"status": "error", "output": "",
                "error": f"preset inconnu: {preset} (valides: {', '.join(OBJECTION_PRESETS)})"}
    if not check_objection():
        return {"status": "error", "output": "",
                "error": "objection non installé — pip install objection"}

    command = OBJECTION_PRESETS[preset]
    if extra_arg:
        command = f"{command} {extra_arg}"

    try:
        proc = subprocess.run(_build_cmd(bundle_id, command),
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout.decode() if isinstance(e.stdout, bytes) else e.stdout) or ""
        if output_path:
            Path(output_path).write_text(out, encoding="utf-8")
        return {"status": "timeout", "output": out, "error": f"timeout {timeout}s"}
    except Exception as e:
        return {"status": "error", "output": "", "error": str(e)}

    combined = (proc.stdout or "") + (proc.stderr or "")
    if output_path:
        Path(output_path).write_text(combined, encoding="utf-8")
    if proc.returncode == 0:
        return {"status": "success", "output": combined, "error": None}
    return {"status": "error", "output": combined,
            "error": (proc.stderr or proc.stdout or "échec")[:400]}


def run_objection_interactive(bundle_id: str) -> int:
    """Lance objection en REPL, stdio hérité (mode interactif)."""
    if not check_objection():
        print("[!] objection non installé — pip install objection")
        return 1
    return subprocess.call(["objection", "-g", bundle_id, "explore"])


BATCH_PRESETS = ("cookies", "prefs", "keychain", "pasteboard", "env", "files")


def batch_recon(bundle_id: str, output_dir: Path,
                timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Lance les presets de recon en séquence → output_dir/<preset>.txt + rapport JSON."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    run = success = failed = 0
    for preset in BATCH_PRESETS:
        run += 1
        out_file = output_dir / f"{preset}.txt"
        result = run_objection_preset(bundle_id, preset, output_path=out_file, timeout=timeout)
        results[preset] = result
        if result["status"] == "success":
            success += 1
        else:
            failed += 1
    stats: dict[str, Any] = {"run": run, "success": success, "failed": failed}
    report = {
        "bundle_id": bundle_id,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "stats": stats,
        "results": {k: {"status": v["status"], "error": v["error"], "bytes": len(v["output"])}
                    for k, v in results.items()},
    }
    (output_dir / "objection_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return {**stats, "report": str(output_dir / "objection_report.json")}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="objection_wrapper",
                                     description="Wrapper Objection — recon runtime iOS")
    parser.add_argument("-b", "--bundle-id", required=True, dest="bundle_id")
    parser.add_argument("--cmd", help="Preset: " + ", ".join(OBJECTION_PRESETS.keys()))
    parser.add_argument("--arg", help="Argument additionnel pour le preset")
    parser.add_argument("-o", "--output", help="Répertoire de sortie pour batch-recon")
    parser.add_argument("--batch", action="store_true", help="Lance tous les presets en séquence")
    parser.add_argument("--interactive", action="store_true", help="Mode REPL interactif")
    args = parser.parse_args(argv)

    if not check_objection():
        print("[!] objection non installé — pip install objection")
        return 1

    if args.interactive:
        return run_objection_interactive(args.bundle_id)
    if args.batch:
        stats = batch_recon(args.bundle_id, Path(args.output or "./objection_out"))
        print(f"[+] batch: {stats['success']}/{stats['run']} OK → {stats['report']}")
        return 0 if stats["failed"] == 0 else 1
    if args.cmd:
        result = run_objection_preset(args.bundle_id, args.cmd, extra_arg=args.arg)
        print(result["output"] or result["error"] or "")
        return 0 if result["status"] == "success" else 1

    print("[*] presets disponibles : " + ", ".join(OBJECTION_PRESETS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
