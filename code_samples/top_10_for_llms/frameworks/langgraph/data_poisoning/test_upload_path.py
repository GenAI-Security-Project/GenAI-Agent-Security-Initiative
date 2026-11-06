"""Regression tests for CV upload confinement. No Streamlit import."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from upload_path import UploadPathError, safe_cv_path


class SafeCvPathTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self._tmp.name)
        self.folder = self.root / "cvs"
        self.folder.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_plain_pdf_stays_inside_cvs(self) -> None:
        dest = safe_cv_path(self.folder, "Candidate One.pdf")
        self.assertEqual(dest.parent, self.folder.resolve())
        self.assertTrue(str(dest).lower().endswith(".pdf"))
        dest.write_bytes(b"%PDF-1.4")
        self.assertTrue(dest.is_file())
        self.assertEqual(dest.read_bytes(), b"%PDF-1.4")

    def test_payloads_that_escape_os_path_join_are_rejected(self) -> None:
        outside = self.root / "secret.txt"
        outside.write_text("TOP-SECRET", encoding="utf-8")
        escaping = [
            r"..\secret.txt",
            "../secret.txt",
            str(outside),
            str(self.root / "pwned.pdf"),
            r"C:\outside\pwned.pdf",
        ]
        for name in escaping:
            joined = Path(os.path.join(str(self.folder), name)).resolve()
            self.assertNotEqual(joined.parent, self.folder.resolve(), name)
            with self.assertRaises(UploadPathError, msg=name):
                safe_cv_path(self.folder, name)
        for name in ("/etc/passwd.pdf", "nested/cv.pdf", "cv.pdf:stream"):
            with self.assertRaises(UploadPathError, msg=name):
                safe_cv_path(self.folder, name)
        self.assertEqual(outside.read_text(encoding="utf-8"), "TOP-SECRET")
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_non_pdf_and_empty_names_are_rejected(self) -> None:
        for name in ("", "   ", "notes.txt", ".", "..", "cv.PDF.exe", None, 12):
            with self.assertRaises(UploadPathError, msg=repr(name)):
                safe_cv_path(self.folder, name)


if __name__ == "__main__":
    unittest.main()
