#!/usr/bin/env python3
"""Automated verifier for the zero-dependency ASI reference samples.

Each sample under ``frameworks/python_stdlib/<sample_name>/`` is expected
to follow the layout documented in ``code_samples/CONTRIBUTING.md``:

* ``README.md``  -- functionality, vulnerability writeup, prerequisites.
* ``Dockerfile``  -- a reproducible way to run the sample locally.
* ``main.py``     -- a runnable demonstration with no third-party
  dependencies (standard library only).
* at least one ``test_*.py`` file runnable via ``python -m unittest``.

This script discovers every sample directory, checks that the required
files are present, and then executes ``main.py`` and the ``unittest``
suite for each sample in a subprocess, failing loudly (with the captured
stdout/stderr) if any sample regresses. It is intended to be run both
locally and from CI (see ``.github/workflows/verify-asi-samples.yml``)
so that the many independently contributed ASI01-ASI10 samples keep
demonstrating their controls as the tree grows.

Usage:
    python verify_asi_samples.py [--root PATH] [--timeout SECONDS]

Exit status is non-zero if any discovered sample is missing a required
file, fails to run, or fails its unit tests.
"""
from __future__ import annotations

import argparse
import dataclasses
import subprocess
import sys
from pathlib import Path

REQUIRED_FILES = ("README.md", "Dockerfile", "main.py")
DEFAULT_TIMEOUT_SECONDS = 120


@dataclasses.dataclass
class SampleResult:
    name: str
    path: Path
    missing_files: list[str] = dataclasses.field(default_factory=list)
    missing_tests: bool = False
    main_ok: bool | None = None
    main_output: str = ""
    tests_ok: bool | None = None
    tests_output: str = ""

    @property
    def ok(self) -> bool:
        if self.missing_files or self.missing_tests:
            return False
        return bool(self.main_ok) and bool(self.tests_ok)


def discover_sample_dirs(root: Path) -> list[Path]:
    """Return every immediate sample directory under ``root``.

    A directory counts as a sample if it is not hidden/underscored and
    contains at least one of the required files, so that unrelated
    scratch directories are skipped rather than reported as failures.
    """
    if not root.is_dir():
        return []
    samples = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.name.startswith((".", "_")):
            continue
        if any((entry / required).exists() for required in REQUIRED_FILES):
            samples.append(entry)
    return samples


def _has_test_module(sample_dir: Path) -> bool:
    return any(sample_dir.glob("test_*.py"))


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return False, f"TIMEOUT after {timeout}s running {' '.join(cmd)}\n{exc}"
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output


def verify_sample(sample_dir: Path, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> SampleResult:
    result = SampleResult(name=sample_dir.name, path=sample_dir)
    result.missing_files = [f for f in REQUIRED_FILES if not (sample_dir / f).exists()]
    result.missing_tests = not _has_test_module(sample_dir)

    if (sample_dir / "main.py").exists():
        result.main_ok, result.main_output = _run(
            [sys.executable, "-B", "main.py"], sample_dir, timeout
        )
    else:
        result.main_ok = False
        result.main_output = "main.py not found"

    if not result.missing_tests:
        result.tests_ok, result.tests_output = _run(
            [sys.executable, "-B", "-m", "unittest", "discover", "-v"], sample_dir, timeout
        )
    else:
        result.tests_ok = False
        result.tests_output = "no test_*.py module found"

    return result


def verify_all(root: Path, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> list[SampleResult]:
    return [verify_sample(sample_dir, timeout) for sample_dir in discover_sample_dirs(root)]


def format_report(results: list[SampleResult]) -> str:
    if not results:
        return "No ASI python_stdlib samples discovered; nothing to verify."

    lines = []
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        lines.append(f"[{status}] {result.name}")
        if result.missing_files:
            lines.append(f"    missing required files: {', '.join(result.missing_files)}")
        if result.missing_tests:
            lines.append("    missing a test_*.py module")
        if result.main_ok is False:
            lines.append("    main.py failed:")
            lines.extend(f"      {line}" for line in result.main_output.splitlines()[-20:])
        if result.tests_ok is False and not result.missing_tests:
            lines.append("    unittest discover failed:")
            lines.extend(f"      {line}" for line in result.tests_output.splitlines()[-20:])

    passed = sum(1 for r in results if r.ok)
    lines.append(f"\n{passed}/{len(results)} samples passed.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent / "frameworks" / "python_stdlib",
        help="Directory containing the ASI python_stdlib samples (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-command timeout in seconds (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    results = verify_all(args.root, args.timeout)
    print(format_report(results))

    if any(not r.ok for r in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
