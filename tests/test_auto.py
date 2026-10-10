"""Tests du pipeline plug & play (run_auto) — device entièrement mocké."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import iphone_afu as m
from iphone_afu import run_auto

NO_EMIT = lambda _msg: None  # noqa: E731


def _fake_ld():
    ld = MagicMock()
    ld.pair_record = {"UDID": "00008030-TEST"}
    return ld


def _happy_patches(out_dir: Path):
    """Patches communs : device OK, extraction OK, syslog OK."""
    def fake_run(cmd, **kwargs):
        if "--output" in cmd:
            target = Path(cmd[cmd.index("--output") + 1])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("log line\n")
        return MagicMock(returncode=0, stdout="", stderr="")

    return [
        patch.object(m, "tunnel_is_active", return_value=True),
        patch.object(m, "collect_device_info", return_value={"DeviceName": "iPhone 16 Pro",
                                                             "ProductType": "iPhone17,1",
                                                             "ProductVersion": "18.4"}),
        patch.object(m, "extract_installed_apps", return_value=[{"bundle_id": "com.a"}]),
        patch.object(m, "extract_dcim", return_value={"files": 3, "bytes": 4096,
                                                      "errors": [], "retries": 0}),
        patch.object(m, "extract_backup", return_value={"status": "success",
                                                        "path": str(out_dir / "backup")}),
        patch.object(m, "scan_directory", return_value={"scanned_files": 2, "scanned_bytes": 10,
                                                        "findings": []}),
        patch.object(m.subprocess, "run", side_effect=fake_run),
    ]


def test_run_auto_with_record_happy_path(tmp_path):
    rec = tmp_path / "afu_record.json"
    rec.write_text("{}")
    out = tmp_path / "out"
    ctxs = _happy_patches(out)
    with patch.object(m, "load_pairing_record", return_value=_fake_ld()):
        for c in ctxs:
            c.start()
        try:
            report = run_auto(out, record_path=rec, wait=0, emit=NO_EMIT)
        finally:
            for c in ctxs:
                c.stop()
    assert report["ok"] is True
    names = [s["name"] for s in report["stages"]]
    assert {"info device", "apps", "dcim", "backup", "syslog", "scan données"} <= set(names)
    for f in ("auto_report.json", "device.json", "apps.json", "syslog.txt", "findings.json"):
        assert (out / f).exists(), f
    assert report["device"]["source"].startswith("record")


def test_run_auto_no_device_reports_error(tmp_path):
    out = tmp_path / "out"
    with patch.object(m, "get_connected_devices", return_value=[]):
        report = run_auto(out, record_path=None, wait=0, emit=NO_EMIT)
    assert report["ok"] is False
    assert report["stages"][0]["name"] == "connexion device"
    assert "aucun device" in report["stages"][0]["detail"]
    assert (out / "auto_report.json").exists()


def test_run_auto_skip_stages(tmp_path):
    rec = tmp_path / "rec.json"
    rec.write_text("{}")
    out = tmp_path / "out"
    ctxs = _happy_patches(out)
    with patch.object(m, "load_pairing_record", return_value=_fake_ld()):
        for c in ctxs:
            c.start()
        try:
            report = run_auto(out, record_path=rec, wait=0,
                              skip=("backup", "syslog", "dcim"), emit=NO_EMIT)
        finally:
            for c in ctxs:
                c.stop()
    names = [s["name"] for s in report["stages"]]
    assert "dcim" not in names
    assert "backup" not in names
    assert "syslog" not in names
    assert "scan données" in names
    assert report["ok"] is True


def test_run_auto_pairs_live_and_saves_record(tmp_path):
    rec = tmp_path / "new_record.json"          # n'existe pas encore
    out = tmp_path / "out"
    ld = _fake_ld()
    device = {"udid": "00008030-TEST", "name": "iPhone 16 Pro", "trusted": True, "lockdown": ld}
    ctxs = _happy_patches(out)
    with patch.object(m, "get_connected_devices", return_value=[device]), \
         patch.object(m, "save_pairing_record", return_value=True) as save_mock:
        for c in ctxs:
            c.start()
        try:
            report = run_auto(out, record_path=rec, wait=0, emit=NO_EMIT)
        finally:
            for c in ctxs:
                c.stop()
    assert save_mock.called
    args, kwargs = save_mock.call_args
    assert args[0] is ld
    assert report["ok"] is True
    assert "device live" in report["device"]["source"]


def test_run_auto_untrusted_device_trust_flow(tmp_path):
    out = tmp_path / "out"
    ld = _fake_ld()
    device = {"udid": "00008030-TEST", "name": "NOT TRUSTED", "trusted": False, "lockdown": None}
    ctxs = _happy_patches(out)
    with patch.object(m, "get_connected_devices", return_value=[device]), \
         patch.object(m, "wait_for_trust", return_value=ld):
        for c in ctxs:
            c.start()
        try:
            report = run_auto(out, record_path=None, wait=1, emit=NO_EMIT)
        finally:
            for c in ctxs:
                c.stop()
    assert report["ok"] is True
    assert "trust live" in report["device"]["source"]
