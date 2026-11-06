"""Steps 5 and 6 gates: severity, ingestion and the API end to end."""
import importlib
import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.cli import main as cli_main
from app.ingest.files import IngestError, extract_zip, select_files, write_snippet
from app.report import severity
from app.schema import Finding

TARGETS = Path(__file__).resolve().parents[2] / "targets"


def zip_dir(folder: Path, prefix: str = "") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for p in folder.rglob("*.py"):
            zf.write(p, prefix + p.relative_to(folder).as_posix())
    return buf.getvalue()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ZDS_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("ZDS_WORKSPACE", str(tmp_path / "ws"))
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


# ---- severity -------------------------------------------------------------
def _f(**kw):
    base = dict(id="F", scan_id="S", file="a.py", line=1, cwe="CWE-78", sink="os.system",
                detector="taint-direct", confidence_tier="reachable")
    return Finding(**{**base, **kw})


def test_severity_formula():
    g = severity.grade(_f(), public_route=True)
    assert g.severity == 9.0  # 6.0 + 1.5 + 1.0 + 0.5
    assert g.severity_factors["base"] == 6.0


def test_unreachable_scores_low():
    g = severity.grade(_f(confidence_tier="pattern-match"), public_route=True)
    assert g.severity == 6.0 and g.severity_factors["public_route"] == 0.0


def test_severity_capped():
    g = severity.grade(_f(confidence_tier="proof-confirmed"), public_route=True)
    assert g.severity == 9.5
    assert severity.label(9.5) == "critical"


# ---- ingestion ------------------------------------------------------------
def test_zip_slip_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.py", "x = 1")
    with pytest.raises(IngestError):
        extract_zip(buf.getvalue(), tmp_path / "out")


def test_oversized_zip_rejected(tmp_path):
    with pytest.raises(IngestError):
        extract_zip(b"0" * (50 * 1024 * 1024 + 1), tmp_path / "out")


def test_single_folder_zip_unwrapped(tmp_path):
    root = extract_zip(zip_dir(TARGETS / "cmd_app", "cmd_app/"), tmp_path / "out")
    assert (root / "app.py").exists()


def test_filter_skips_venv_and_tests(tmp_path):
    for rel in ("app.py", "venv/lib.py", "tests/test_x.py", "README.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x = 1\n")
    keep, skipped = select_files(tmp_path)
    assert [p.name for p in keep] == ["app.py"] and skipped == 3


def test_snippet_without_imports(tmp_path):
    code = "@app.route('/x')\ndef x():\n    import os\n    os.system('ls ' + request.args['d'])\n"
    root = write_snippet(code, tmp_path / "snip")
    assert "from flask import" in (root / "app.py").read_text()


# ---- API ------------------------------------------------------------------
def test_zip_scan_end_to_end(client):
    r = client.post("/api/scans", files={"file": ("cmd_app.zip", zip_dir(TARGETS / "cmd_app"))})
    assert r.status_code == 202
    sid = r.json()["id"]
    scan = client.get(f"/api/scans/{sid}").json()
    assert scan["status"] == "done" and scan["counts"]["CWE-78"] == 5
    findings = client.get(f"/api/scans/{sid}/findings").json()
    top = findings[0]
    assert top["severity"] >= 7 and top["owasp"] == "A03:2021 Injection" and top["fix_suggestion"]
    assert any(f["detector"] == "taint-wrapper" for f in findings)
    assert "def ping" in client.get(f"/api/scans/{sid}/file", params={"path": "app.py"}).text


def test_status_change_persists(client):
    sid = client.post("/api/scans", files={"file": ("p.zip", zip_dir(TARGETS / "path_app"))}).json()["id"]
    fid = client.get(f"/api/scans/{sid}/findings").json()[0]["id"]
    assert client.patch(f"/api/scans/{sid}/findings/{fid}", json={"status": "fixed"}).status_code == 200
    assert client.get(f"/api/scans/{sid}/findings/{fid}").json()["status"] == "fixed"
    assert client.patch(f"/api/scans/{sid}/findings/{fid}", json={"status": "nope"}).status_code == 422


def test_bad_zip_400(client):
    assert client.post("/api/scans", files={"file": ("x.zip", b"not a zip")}).status_code == 400


def test_snippet_endpoint(client):
    code = "@app.route('/x')\ndef x():\n    import os\n    os.system('ls ' + request.args['d'])\n"
    sid = client.post("/api/snippet", json={"code": code}).json()["id"]
    findings = client.get(f"/api/scans/{sid}/findings").json()
    assert [f["cwe"] for f in findings] == ["CWE-78"]


def test_cli_exit_code(capsys):
    assert cli_main(["scan", str(TARGETS / "sqli_app")]) == 1
    assert "cursor.execute" in capsys.readouterr().out
