#!/usr/bin/env python3
"""Unit tests for ``verify_asi_samples.py``.

These tests build small synthetic sample trees in an isolated temporary
directory (never inside the repository) so that the verifier's
discovery, pass, and failure-reporting logic is exercised without
depending on any particular ASI sample that may or may not be merged
yet under ``frameworks/python_stdlib/``.
"""
from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

import verify_asi_samples as vas

PASSING_MAIN = "print('demo ok')\n"
FAILING_MAIN = "import sys\nsys.exit(1)\n"
PASSING_TEST = textwrap.dedent(
    """
    import unittest

    class T(unittest.TestCase):
        def test_ok(self):
            self.assertTrue(True)

    if __name__ == "__main__":
        unittest.main()
    """
)
FAILING_TEST = textwrap.dedent(
    """
    import unittest

    class T(unittest.TestCase):
        def test_fails(self):
            self.assertTrue(False)

    if __name__ == "__main__":
        unittest.main()
    """
)


def _write_sample(
    root: Path,
    name: str,
    *,
    main_src: str | None = PASSING_MAIN,
    test_src: str | None = PASSING_TEST,
    readme: bool = True,
    dockerfile: bool = True,
) -> Path:
    sample_dir = root / name
    sample_dir.mkdir(parents=True)
    if readme:
        (sample_dir / "README.md").write_text("# sample\n", encoding="utf-8")
    if dockerfile:
        (sample_dir / "Dockerfile").write_text("FROM python:3.11\n", encoding="utf-8")
    if main_src is not None:
        (sample_dir / "main.py").write_text(main_src, encoding="utf-8")
    if test_src is not None:
        (sample_dir / "test_sample.py").write_text(test_src, encoding="utf-8")
    return sample_dir


class DiscoverSampleDirsTests(unittest.TestCase):
    def test_discovers_only_directories_with_required_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_sample(root, "good_sample")
            (root / "_scratch").mkdir()
            (root / "_scratch" / "main.py").write_text("print(1)\n", encoding="utf-8")
            (root / "not_a_sample").mkdir()

            discovered = vas.discover_sample_dirs(root)

            self.assertEqual([p.name for p in discovered], ["good_sample"])

    def test_missing_root_returns_empty_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist"
            self.assertEqual(vas.discover_sample_dirs(missing), [])


class VerifySampleTests(unittest.TestCase):
    def test_passing_sample_is_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample_dir = _write_sample(Path(tmp), "passing")
            result = vas.verify_sample(sample_dir, timeout=30)

            self.assertTrue(result.ok)
            self.assertEqual(result.missing_files, [])
            self.assertFalse(result.missing_tests)
            self.assertTrue(result.main_ok)
            self.assertTrue(result.tests_ok)

    def test_missing_required_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample_dir = _write_sample(Path(tmp), "no_readme", readme=False)
            result = vas.verify_sample(sample_dir, timeout=30)

            self.assertFalse(result.ok)
            self.assertIn("README.md", result.missing_files)

    def test_missing_test_module_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample_dir = _write_sample(Path(tmp), "no_tests", test_src=None)
            result = vas.verify_sample(sample_dir, timeout=30)

            self.assertFalse(result.ok)
            self.assertTrue(result.missing_tests)

    def test_failing_main_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample_dir = _write_sample(Path(tmp), "bad_main", main_src=FAILING_MAIN)
            result = vas.verify_sample(sample_dir, timeout=30)

            self.assertFalse(result.ok)
            self.assertFalse(result.main_ok)

    def test_failing_unit_test_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample_dir = _write_sample(Path(tmp), "bad_test", test_src=FAILING_TEST)
            result = vas.verify_sample(sample_dir, timeout=30)

            self.assertFalse(result.ok)
            self.assertFalse(result.tests_ok)


class VerifyAllAndReportTests(unittest.TestCase):
    def test_verify_all_discovers_and_checks_every_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_sample(root, "good_sample")
            _write_sample(root, "broken_sample", main_src=FAILING_MAIN)

            results = vas.verify_all(root, timeout=30)

            self.assertEqual({r.name for r in results}, {"good_sample", "broken_sample"})
            by_name = {r.name: r for r in results}
            self.assertTrue(by_name["good_sample"].ok)
            self.assertFalse(by_name["broken_sample"].ok)

    def test_report_is_empty_message_when_no_samples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = vas.format_report(vas.verify_all(Path(tmp), timeout=30))
            self.assertIn("No ASI python_stdlib samples discovered", report)

    def test_report_mentions_failure_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_sample(root, "broken_sample", main_src=FAILING_MAIN)
            report = vas.format_report(vas.verify_all(root, timeout=30))

            self.assertIn("FAIL", report)
            self.assertIn("broken_sample", report)
            self.assertIn("main.py failed", report)


class MainEntryPointTests(unittest.TestCase):
    def test_main_returns_zero_for_passing_samples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_sample(root, "good_sample")
            self.assertEqual(vas.main(["--root", str(root), "--timeout", "30"]), 0)

    def test_main_returns_nonzero_for_failing_samples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_sample(root, "broken_sample", main_src=FAILING_MAIN)
            self.assertEqual(vas.main(["--root", str(root), "--timeout", "30"]), 1)

    def test_main_returns_zero_when_root_has_no_samples_yet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "python_stdlib"
            self.assertEqual(vas.main(["--root", str(root), "--timeout", "30"]), 0)


if __name__ == "__main__":
    unittest.main()
