#!/usr/bin/env python3
"""
Diagnostic USB + usbmuxd pour VM Linux.
Détecte : VMware / VirtualBox / natif, état usbmuxd, device Apple visible, trust.
Usage: python check_vm_usb.py
Exit code: 0 si tout OK, 1 si au moins un check échoue.
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


def _run(cmd, timeout=10):
    """Exécute une commande, retourne (returncode, stdout+stderr). -1 si binaire absent."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return -1, f"{cmd[0]} introuvable"
    except Exception as e:
        return -1, str(e)


def _read(path):
    try:
        return Path(path).read_text(errors="ignore").strip()
    except OSError:
        return ""


def check_vm():
    """Détecte l'hyperviseur : VMware / VirtualBox / KVM / bare-metal."""
    vendor = _read("/sys/class/dmi/id/sys_vendor")
    product = _read("/sys/class/dmi/id/product_name")
    cpuinfo = _read("/proc/cpuinfo").lower()
    haystack = f"{vendor} {product} {cpuinfo}".lower()
    if "vmware" in haystack:
        vm = "VMware"
    elif "virtualbox" in haystack or "innotek" in haystack:
        vm = "VirtualBox"
    elif "kvm" in haystack or "qemu" in haystack:
        vm = "KVM/QEMU"
    elif vendor or product:
        vm = "bare-metal"
    else:
        rc, out = _run(["dmidecode", "-s", "system-product-name"])
        vm = out.strip() if rc == 0 else "inconnu"
    detail = f"{vendor} {product}".strip() or vm
    return {"check": "Détection VM", "status": True, "detail": f"{vm} — {detail}", "fix": None}


def check_usbmuxd():
    rc, out = _run(["systemctl", "is-active", "usbmuxd"])
    state = out.strip().splitlines()[0] if out.strip() else "n/a"
    active = rc == 0 and state == "active"
    sockets = [p for p in ("/var/run/usbmuxd", "/run/usbmuxd") if Path(p).exists()]
    ok = active or bool(sockets)
    return {
        "check": "usbmuxd actif",
        "status": ok,
        "detail": f"systemctl={state}, socket={'oui' if sockets else 'non'}",
        "fix": None if ok else "sudo systemctl enable --now usbmuxd",
    }


def check_apple_usb():
    devices = []
    rc, out = _run(["lsusb"])
    if rc == 0:
        devices = [line.strip() for line in out.splitlines() if "05ac:" in line.lower()]
    else:
        for vfile in Path("/sys/bus/usb/devices").glob("*/idVendor"):
            if _read(str(vfile)).lower() == "05ac":
                devices.append(vfile.parent.name)
    ok = bool(devices)
    return {
        "check": "Device Apple visible USB",
        "status": ok,
        "detail": devices[0] if devices else "aucun vendor Apple (05ac) sur le bus USB",
        "fix": None if ok else "Active le USB passthrough (VM Settings → USB → Apple iPhone)",
    }


def check_idevice():
    """Retourne (résultat du check, liste des UDIDs détectés)."""
    if shutil.which("idevice_id") is None:
        return {
            "check": "Device reconnu (usbmuxd)",
            "status": False,
            "detail": "idevice_id introuvable",
            "fix": "sudo apt install libimobiledevice-utils",
        }, []
    rc, out = _run(["idevice_id", "-l"])
    udids = [line.strip() for line in out.splitlines() if line.strip()]
    ok = rc == 0 and bool(udids)
    detail = f"{len(udids)} device(s): {', '.join(udids)}" if udids else (out.strip() or "aucun device")
    return {
        "check": "Device reconnu (usbmuxd)",
        "status": ok,
        "detail": detail,
        "fix": None if ok else "Vérifie le passthrough USB puis: sudo systemctl restart usbmuxd",
    }, udids


def check_trust(udids):
    if not udids:
        return {
            "check": "Trust établi",
            "status": False,
            "detail": "aucun device — trust non vérifiable",
            "fix": "Déverrouille l'iPhone puis accepte 'Faire confiance'",
        }
    rc, out = _run(["ideviceinfo", "-u", udids[0]])
    ok = rc == 0
    detail = "trust OK" if ok else (out.strip().splitlines()[0] if out.strip() else "échec ideviceinfo")
    return {
        "check": "Trust établi",
        "status": ok,
        "detail": detail,
        "fix": None if ok else "Déverrouille l'iPhone puis accepte 'Faire confiance' (ou: python iphone_afu.py pair)",
    }


def check_vmware(vm_label):
    if "vmware" not in vm_label.lower():
        return {"check": "USB passthrough VMware", "status": True, "detail": "non applicable", "fix": None}
    services = []
    for svc in ("vmware-toolsd", "open-vm-tools", "vmtoolsd"):
        rc, out = _run(["systemctl", "is-active", svc])
        if rc == 0 and out.strip().splitlines() and out.strip().splitlines()[0] == "active":
            services.append(svc)
    usb_proc = Path("/proc/bus/usb/devices").exists()
    ok = bool(services) or usb_proc
    return {
        "check": "USB passthrough VMware",
        "status": ok,
        "detail": f"services={' '.join(services) or 'aucun'}, /proc/bus/usb/devices={'oui' if usb_proc else 'non'}",
        "fix": None if ok else "Installe open-vm-tools + active le USB passthrough dans VMware",
    }


def check_groups():
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    rc, out = _run(["id", "-nG", user]) if user else (-1, "")
    groups = out.split()
    has_plugdev = "plugdev" in groups
    has_dialout = "dialout" in groups
    ok = has_plugdev
    return {
        "check": "Groupes utilisateur",
        "status": ok,
        "detail": f"user={user or '?'} plugdev={'oui' if has_plugdev else 'non'} dialout={'oui' if has_dialout else 'non'}",
        "fix": None if ok else "sudo usermod -aG plugdev,dialout $USER puis reconnecte la session",
    }


def main() -> int:
    if platform.system() != "Linux":
        print(f"[!] check_vm_usb.py cible Linux (détecté: {platform.system()})")
        return 1

    vm_info = check_vm()
    results = [vm_info, check_usbmuxd(), check_apple_usb()]
    idev, udids = check_idevice()
    results.append(idev)
    results.append(check_trust(udids))
    results.append(check_vmware(vm_info["detail"]))
    results.append(check_groups())

    if RICH:
        table = Table(title="Diagnostic USB / usbmuxd")
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Détail", style="dim")
        table.add_column("Fix", style="yellow")
        for r in results:
            status = "[green]✓ OK[/green]" if r["status"] else "[red]✗ FAIL[/red]"
            table.add_row(r["check"], status, r["detail"], r["fix"] or "—")
        console.print(table)
    else:
        for r in results:
            tag = "[OK]  " if r["status"] else "[FAIL]"
            line = f"{tag} {r['check']} — {r['detail']}"
            if not r["status"] and r["fix"]:
                line += f" → {r['fix']}"
            print(line)

    failed = [r for r in results if not r["status"]]
    if failed:
        print(f"\n[!] {len(failed)} check(s) en échec — corrige les fixes ci-dessus ou relance setup.sh.")
        return 1
    print("\n[+] Tous les checks sont OK — device prêt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
