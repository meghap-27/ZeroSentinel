"""Scan a folder end to end: detect, grade, tag. Shared by the API and the CLI."""
import time
from pathlib import Path

from .detect.callgraph import build_project
from .detect.scanner import scan_project
from .ingest.files import select_files
from .report import owasp, severity
from .schema import Finding


def _public(project, f: Finding) -> bool:
    entry = f.path[0].removesuffix("()") if f.path else ""
    for fn in project.functions.values():
        if fn.name == entry and fn.route:
            return not fn.has_auth
    return False


def run_scan(root: Path, scan_id: str) -> dict:
    start = time.perf_counter()
    files, skipped = select_files(root)
    project = build_project(root, files)
    raw = scan_project(root, scan_id, project=project)
    graded = []
    for f in raw:
        f = f.model_copy(update={"owasp": owasp.tag(f.cwe), "fix_suggestion": owasp.fix_for(f.cwe)})
        graded.append(severity.grade(f, _public(project, f)))
    graded.sort(key=lambda f: (-f.severity, f.file, f.line))
    graded = [f.model_copy(update={"id": f"F-{i:03d}"}) for i, f in enumerate(graded, 1)]
    contents = {p.relative_to(root).as_posix(): p.read_text(errors="replace") for p in files}
    return {"findings": graded, "files": contents, "skipped": skipped,
            "duration": round(time.perf_counter() - start, 3)}
