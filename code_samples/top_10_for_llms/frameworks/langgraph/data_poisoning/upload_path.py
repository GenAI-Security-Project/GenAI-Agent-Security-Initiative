"""Confine CV uploads to a single directory.

The reviewer is a prompt-injection exercise. The upload control must not also
be an arbitrary file write: client filenames are not paths.
"""

from __future__ import annotations

from pathlib import Path


class UploadPathError(ValueError):
    """The client filename is not a safe CV name inside the upload directory."""


def safe_cv_path(upload_folder: str | Path, filename: object) -> Path:
    """Return the resolved PDF path inside ``upload_folder``, or raise.

    Rejects non-strings, absolute paths, separators, parent segments, and any
    destination that does not stay in the resolved upload directory. A symlink
    at the destination is rejected so a link cannot retarget the write.
    """
    if not isinstance(filename, str):
        raise UploadPathError("CV filename must be a string")
    if not filename or filename != filename.strip() or "\x00" in filename:
        raise UploadPathError("CV filename is empty or contains whitespace or NUL")
    if filename != Path(filename).name or any(sep in filename for sep in ("/", "\\", ":")):
        raise UploadPathError("CV filename must be a single path segment")
    if filename in {".", ".."}:
        raise UploadPathError("CV filename must not be a relative segment")
    if not filename.lower().endswith(".pdf"):
        raise UploadPathError("CV upload must use a .pdf name")

    root = Path(upload_folder).resolve()
    dest = root / filename
    if dest.is_symlink():
        raise UploadPathError("CV upload must not replace a symlink")
    resolved = dest.resolve()
    if resolved.parent != root:
        raise UploadPathError("CV upload escapes the cvs directory")
    if resolved.is_symlink():
        raise UploadPathError("CV upload must not replace a symlink")
    return resolved
