# Changelog

All notable changes to iphone-afu are documented here.
Format: [Semantic Versioning](https://semver.org/)

## [Unreleased]

### Added — pairing record recovery & reuse
- `record-find` — localise les pairing records multi-OS (iTunes, iMazing, 3uTools, lockdownd, `~/.iphone_afu/`) avec validation des 4 champs requis
- `record-test` — test en 5 étapes contre le device branché (parse → lockdown → AFU → AFC → services)
- `record-import` — import multi-machine + installation aux emplacements standard (Linux/macOS/Windows)
- `auto` — étape record-test automatique avant extraction + `--skip record-test`
- `docs/PAIRING_RECORD_RECOVERY.md` — guide complet (chemins par OS, BFU, Reset Location & Privacy)
- 16 nouveaux tests (90 total, sans device)

### Added — v2 targets
- `macho` — analyse Mach-O complète : PIE/canary/ARC/FairPlay + bypass vectors (skill: binary-protection-bypass)
- `proxy` — MITM proxy mitmproxy + SSL pinning bypass Frida (skill: mobile-ssl-pinning-bypass)
- `objection` — wrapper Objection avec 10 presets du skill ios-pentesting-tricks §5
- `strings-hunt` — secret hunting regex + entropie Shannon + score d'obfuscation
- `plist-dump` — extraction des 9 data storage locations du skill ios-pentesting-tricks §7
- `network-recon` — parse syslog → domaines + DNS resolution + GeoIP
- `report` — rapport HTML standalone dark-theme depuis auto_out/
- `class-dump` — dump statique classes ObjC + symboles Swift
- CI GitHub Actions (Python 3.10/3.11/3.12, ruff, mypy, ShellCheck, bandit)
- MIT License

## [1.0.0] — 2026-10-10

### Added — v1
- `check` `pair` `dcim` `backup` `apps` `keychain` `tunnel`
- `info` `syslog` `audit` `aasa` `scan` `bypass` `tui` `auto`
- AES-256-GCM pairing records (scrypt)
- Textual TUI avec BundleInputModal
- DeviceContext dataclass avec resolve() et cache
- AFC retry avec backoff linéaire
- Logging structuré RotatingFileHandler
- Manifest DCIM JSON+CSV avec EXIF
- check_vm_usb.py — 7 checks VM/USB
- frida_sideload.sh — 10 étapes gadget sideload
- auto.sh — plug & play wrapper
- 10 tests unitaires mockés
