"""Tests ptp_extractor — gphoto2 entièrement mocké (aucun device requis)."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from modules import ptp_extractor as ptp


@pytest.fixture
def mock_gp():
    m = MagicMock()
    # CameraFilePath() doit rendre une instance fraîche à chaque appel
    m.CameraFilePath.side_effect = lambda: MagicMock()
    with patch.object(ptp, "gp", m, create=True), \
         patch.object(ptp, "GPHOTO", True):
        yield m


def make_camera(files_by_folder=None, folders_by_folder=None):
    cam = MagicMock()
    files_by_folder = files_by_folder or {}
    folders_by_folder = folders_by_folder or {}

    def list_files(folder, ctx):
        if folder in files_by_folder:
            return files_by_folder[folder]
        raise Exception(f"GP_ERROR_IO: {folder}")

    def list_folders(folder, ctx):
        if folder in folders_by_folder:
            return [SimpleNamespace(name=n) for n in folders_by_folder[folder]]
        raise Exception(f"GP_ERROR_IO: {folder}")

    cam.folder_list_files.side_effect = list_files
    cam.folder_list_folders.side_effect = list_folders
    return cam


# 1. detect_camera retourne None si aucun device
def test_detect_camera_no_device(mock_gp):
    mock_gp.Camera.autodetect.return_value = []
    assert ptp.detect_camera(wait=False, timeout=0) is None


def test_detect_camera_success(mock_gp):
    mock_gp.Camera.autodetect.return_value = [("Apple iPhone", "usb:001,002")]
    cam = ptp.detect_camera(wait=False, timeout=0)
    assert cam is not None
    mock_gp.Camera.assert_called()
    assert mock_gp.Camera.return_value.init.called


# 2. check_storage_accessible retourne False si GP_ERROR_IO
def test_storage_not_accessible_on_error(mock_gp):
    cam = make_camera()
    assert ptp.check_storage_accessible(cam, mock_gp.Context()) is False


# 3. check_storage_accessible retourne True si listdir réussit
def test_storage_accessible(mock_gp):
    cam = make_camera(
        files_by_folder={"/store_00010001/DCIM": ["IMG_0001.JPG"]},
        folders_by_folder={"/": ["store_00010001"]},
    )
    assert ptp.check_storage_accessible(cam, mock_gp.Context()) is True
    assert ptp.find_dcim_folder(cam, mock_gp.Context()) == "/store_00010001/DCIM"


# 4. wait_for_unlock retourne None après timeout
def test_wait_for_unlock_timeout(mock_gp):
    cam = make_camera()
    assert ptp.wait_for_unlock(cam, mock_gp.Context(), timeout=0) is None


def test_wait_for_unlock_success(mock_gp):
    cam = make_camera(
        files_by_folder={"/store_00010001/DCIM": []},
        folders_by_folder={"/": ["store_00010001"]},
    )
    assert ptp.wait_for_unlock(cam, mock_gp.Context(), timeout=0) == "/store_00010001/DCIM"


# 5. list_all_files retourne [] sur filesystem vide
def test_list_files_empty(mock_gp):
    cam = make_camera(
        files_by_folder={"/store_00010001/DCIM": []},
        folders_by_folder={"/": ["store_00010001"], "/store_00010001/DCIM": []},
    )
    assert ptp.list_all_files(cam, mock_gp.Context()) == []


# 6. list_all_files filtre les extensions non-media
def test_list_files_extension_filter(mock_gp):
    cam = make_camera(
        files_by_folder={"/store_00010001/DCIM": [
            "IMG_0001.JPG", "IMG_0002.HEIC", "video.MOV", "notes.txt", ".hidden"]},
        folders_by_folder={"/": ["store_00010001"],
                           "/store_00010001/DCIM": ["APPLE100"]},
    )
    cam.folder_list_files.side_effect = lambda folder, ctx: {
        "/store_00010001/DCIM": ["IMG_0001.JPG", "IMG_0002.HEIC", "video.MOV",
                                 "notes.txt", ".hidden"],
        "/store_00010001/DCIM/APPLE100": ["SUB_0001.png", "readme.pdf"],
    }[folder]
    files = ptp.list_all_files(cam, mock_gp.Context())
    names = sorted(str(f.name) for f in files)
    assert names == ["IMG_0001.JPG", "IMG_0002.HEIC", "SUB_0001.png", "video.MOV"]
    assert all(isinstance(f.folder, str) for f in files)


# 7. extract_files stats["copied"] == 1 sur un fichier
def test_extract_single_file(mock_gp, tmp_path):
    cam = make_camera()
    cam.file_get_info.return_value = SimpleNamespace(file=SimpleNamespace(size=1234))

    def file_get(folder, name, type_, ctx):
        cf = MagicMock()

        def save(path):
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"x" * 1234)

        cf.save.side_effect = save
        return cf

    cam.file_get.side_effect = file_get
    f = ptp.PtpFile(folder="/store_00010001/DCIM", name="IMG_0001.JPG")
    stats = ptp.extract_files(cam, mock_gp.Context(), [f], tmp_path)
    assert stats["copied"] == 1
    assert stats["errors"] == 0
    assert stats["total_bytes"] == 1234
    assert (tmp_path / "DCIM" / "IMG_0001.JPG").exists()


# 8. extract_files resume skip fichier déjà présent
def test_extract_resume_skip(mock_gp, tmp_path):
    cam = make_camera()
    cam.file_get_info.return_value = SimpleNamespace(file=SimpleNamespace(size=1234))
    dest = tmp_path / "DCIM" / "IMG_0001.JPG"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"x" * 1234)

    f = ptp.PtpFile(folder="/store_00010001/DCIM", name="IMG_0001.JPG")
    stats = ptp.extract_files(cam, mock_gp.Context(), [f], tmp_path, resume=True)
    assert stats["skipped"] == 1
    assert stats["copied"] == 0
    assert cam.file_get.call_count == 0


def test_extract_retries_then_error(mock_gp, tmp_path):
    cam = make_camera()
    cam.file_get_info.side_effect = Exception("no info")
    cam.file_get.side_effect = Exception("GP_ERROR_IO")
    f = ptp.PtpFile(folder="/store_00010001/DCIM", name="IMG_2.JPG")
    with patch.object(ptp.time, "sleep", return_value=None):
        stats = ptp.extract_files(cam, mock_gp.Context(), [f], tmp_path)
    assert stats["errors"] == 1
    assert cam.file_get.call_count == ptp.RETRIES
    assert stats["error_list"][0]["file"].endswith("IMG_2.JPG")


def test_build_manifest(mock_gp, tmp_path):
    (tmp_path / "DCIM").mkdir()
    (tmp_path / "DCIM" / "a.jpg").write_bytes(b"a" * 10)
    (tmp_path / "DCIM" / "b.mov").write_bytes(b"b" * 20)
    result = ptp.build_manifest(tmp_path)
    assert result["files"] == 2
    import json
    entries = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert {e["path"] for e in entries} == {"DCIM/a.jpg", "DCIM/b.mov"}
    assert all({"path", "size_bytes", "mtime", "ext", "exif_date"} <= set(e) for e in entries)
    assert (tmp_path / "manifest.csv").exists()


def test_module_without_gphoto(monkeypatch):
    monkeypatch.setattr(ptp, "GPHOTO", False)
    with pytest.raises(RuntimeError, match="gphoto2"):
        ptp.detect_camera(wait=False, timeout=0)
