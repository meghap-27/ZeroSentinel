"""Ingestion (L1): zip upload, snippet wrapping and the file filter."""
import io
import zipfile
from pathlib import Path

MAX_ZIP_BYTES = 50 * 1024 * 1024
MAX_UNPACKED_BYTES = 200 * 1024 * 1024
SKIP_DIRS = {"venv", ".venv", "env", "site-packages", "node_modules", "tests", "test",
             "__pycache__", ".git", "vendor", "dist", "build"}
SNIPPET_HEADER = "from flask import Flask, request\napp = Flask(__name__)\n\n"


class IngestError(ValueError):
    pass


def extract_zip(data: bytes, dest: Path) -> Path:
    if len(data) > MAX_ZIP_BYTES:
        raise IngestError("zip is larger than 50 MB")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError("not a valid zip file") from exc
    dest = dest.resolve()
    total = 0
    for info in zf.infolist():
        target = (dest / info.filename).resolve()
        if not target.is_relative_to(dest):
            raise IngestError(f"unsafe path in zip: {info.filename}")
        total += info.file_size
        if total > MAX_UNPACKED_BYTES:
            raise IngestError("zip unpacks to more than 200 MB")
    dest.mkdir(parents=True, exist_ok=True)
    zf.extractall(dest)
    return _single_root(dest)


def _single_root(dest: Path) -> Path:
    """If the zip holds one top-level folder, scan inside it."""
    entries = [p for p in dest.iterdir() if p.name != "__MACOSX"]
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else dest


def select_files(root: Path) -> tuple[list[Path], int]:
    """Python files to scan, and how many other files were skipped."""
    keep, skipped = [], 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        parts = set(p.relative_to(root).parts[:-1])
        if p.suffix == ".py" and not parts & SKIP_DIRS:
            keep.append(p)
        else:
            skipped += 1
    return keep, skipped


def write_snippet(code: str, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    header = "" if "Flask(" in code else SNIPPET_HEADER
    (dest / "app.py").write_text(header + code.strip() + "\n")
    return dest
