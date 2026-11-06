"""FastAPI service (L5). Run: uvicorn app.main:app --reload (from backend/)."""
import os
import shutil
import uuid
from pathlib import Path
from typing import Literal

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .ingest.files import IngestError, extract_zip, write_snippet
from .pipeline import run_scan
from .report.owasp import CWE_NAMES
from .store import Store, dumps

HERE = Path(__file__).resolve().parent
WORK = Path(os.environ.get("ZDS_WORKSPACE", HERE.parent / "workspace"))
store = Store(os.environ.get("ZDS_DB", HERE.parent / "zds.db"))
app = FastAPI(title="ZeroSentinel")


class StatusIn(BaseModel):
    status: Literal["open", "fixed", "accepted"]


class SnippetIn(BaseModel):
    code: str
    name: str = "snippet"


def _execute(scan_id: str, root: Path) -> None:
    try:
        res = run_scan(root, scan_id)
        store.finish_scan(scan_id, res["findings"], res["files"], res["duration"], res["skipped"])
    except Exception as exc:  # surfaced to the UI as a failed scan
        store.fail_scan(scan_id, str(exc))
    finally:
        shutil.rmtree(WORK / scan_id, ignore_errors=True)


def _new_id() -> str:
    return "S-" + uuid.uuid4().hex[:8]


@app.post("/api/scans", status_code=202)
async def create_scan(background: BackgroundTasks, file: UploadFile = File(...),
                      name: str = Form("")) -> dict:
    scan_id = _new_id()
    try:
        root = extract_zip(await file.read(), WORK / scan_id)
    except IngestError as exc:
        raise HTTPException(400, str(exc)) from exc
    store.create_scan(scan_id, name or (file.filename or "upload").removesuffix(".zip"), "zip")
    background.add_task(_execute, scan_id, root)
    return {"id": scan_id}


@app.post("/api/snippet")
def create_snippet(body: SnippetIn) -> dict:
    scan_id = _new_id()
    store.create_scan(scan_id, body.name, "snippet")
    _execute(scan_id, write_snippet(body.code, WORK / scan_id))
    return {"id": scan_id}


@app.get("/api/scans")
def list_scans() -> list[dict]:
    return store.scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    scan = store.scan(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    findings = store.findings(scan_id)
    scan["counts"] = {c: sum(f.cwe == c for f in findings) for c in CWE_NAMES}
    scan["total"] = len(findings)
    return scan


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str) -> list[dict]:
    return [f.model_dump() for f in store.findings(scan_id)]


@app.get("/api/scans/{scan_id}/findings/{finding_id}")
def get_finding(scan_id: str, finding_id: str) -> dict:
    f = store.finding(scan_id, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return f.model_dump()


@app.patch("/api/scans/{scan_id}/findings/{finding_id}")
def patch_finding(scan_id: str, finding_id: str, body: StatusIn) -> dict:
    f = store.set_status(scan_id, finding_id, body.status)
    if not f:
        raise HTTPException(404, "finding not found")
    return f.model_dump()


@app.get("/api/scans/{scan_id}/file", response_class=PlainTextResponse)
def get_file(scan_id: str, path: str) -> str:
    content = store.file(scan_id, path)
    if content is None:
        raise HTTPException(404, "file not found")
    return content


@app.get("/api/scans/{scan_id}/report", response_class=PlainTextResponse)
def get_report(scan_id: str) -> str:
    return dumps(store.findings(scan_id))


DIST = HERE.parents[1] / "frontend" / "dist"
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> FileResponse:
        return FileResponse(DIST / "index.html")
