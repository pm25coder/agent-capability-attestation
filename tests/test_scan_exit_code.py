"""Tests that ``aca scan``'s exit code reflects the verdict it just printed.

``scan`` validated every file in a directory, printed the correct per-file
verdict (``✗ STALE`` / ``✗ INVALID``, ``ERROR:`` lines) and then threw the
verdict away: ``all_valid`` was only consulted when ``--fail-on-stale`` was
passed, so the command exited ``0`` by default. A directory holding nothing but
forged and expired attestations therefore produced a green build — the tool
detected the forgery and the process boundary discarded the detection, which is
the only place a CI system reads.

These tests pin the exit *code*, not the output: the verdict lines were already
correct before the fix, so an output assertion alone cannot catch this class of
defect (see ``tests/test_naive_timestamps.py`` and ``tests/test_future_issued_at.py``,
whose ``scan`` tests assert only on stdout).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from agent_capability_attestation.cli import cli


def _iso(offset: timedelta) -> str:
    return (datetime.now(timezone.utc) + offset).isoformat()


def _attestation(issued_at: str, ttl: int = 300, **extra) -> dict:
    document = {
        "issuer": "agent://planner",
        "subject": "agent://worker",
        "capability": "CAN_READ(store)",
        "issued_at": issued_at,
        "ttl_seconds": ttl,
    }
    document.update(extra)
    return document


def _write(directory, name: str, document: dict):
    path = directory / name
    path.write_text(json.dumps(document))
    return path


def _stale(directory, name: str = "stale.attestation.json"):
    """An attestation that expired long ago — invalid without any flag."""
    return _write(directory, name, _attestation(_iso(timedelta(days=-30)), ttl=60))


def _fresh_unsigned(directory, name: str = "fresh.attestation.json"):
    """A live, unsigned attestation: valid (an absent signature is a warning)."""
    return _write(directory, name, _attestation(_iso(timedelta(0))))


class TestScanExitCode:
    def test_scan_exits_one_when_any_attestation_is_invalid(self, tmp_path):
        """The reported defect: one invalid file, no flag, exit must be 1."""
        _stale(tmp_path)

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output
        assert "STALE" in result.output

    def test_scan_exits_one_for_a_forged_attestation_alongside_a_stale_one(
        self, tmp_path
    ):
        """The issue's exact directory: one expired, one carrying a bogus
        signature. The second file's ERROR is the whole point — it used to be
        printed and then discarded by an exit status of 0."""
        _stale(tmp_path, "a-stale.attestation.json")
        _write(
            tmp_path,
            "b-forged.attestation.json",
            _attestation(
                _iso(timedelta(0)),
                ttl=120,
                subject="agent://mallory",
                capability="CAN_DELETE_ALL(state)",
                signature="ed25519:" + "ab" * 60,
            ),
        )

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output

    def test_scan_exits_zero_when_every_attestation_is_valid(self, tmp_path):
        """Guard the guard: a clean directory must still pass the gate."""
        _fresh_unsigned(tmp_path)

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 0, result.output

    def test_scan_exits_one_when_a_file_cannot_be_read(self, tmp_path):
        """The ``except`` path also feeds the exit code: an unreadable file is
        an invalid result, not a reason to exit 0."""
        (tmp_path / "broken.attestation.json").write_text("{ not json")

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output

    def test_empty_directory_still_exits_zero(self, tmp_path):
        """Nothing to scan is not a failure — unchanged by this fix."""
        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 0, result.output

    def test_report_only_forces_exit_zero_and_still_prints_the_verdict(
        self, tmp_path
    ):
        """The explicit opt-out: the finding is still reported on stdout, only
        the exit status is relaxed."""
        _stale(tmp_path)

        result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--report-only"])

        assert result.exit_code == 0, result.output
        assert "STALE" in result.output

    def test_deprecated_fail_on_stale_is_still_accepted(self, tmp_path):
        """Kept for one release so the documented CI recipe keeps working: it
        is now redundant, but it must not be rejected or change the outcome."""
        _stale(tmp_path)

        result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--fail-on-stale"])

        assert result.exit_code == 1, result.output

    def test_fail_on_stale_and_report_only_are_mutually_exclusive(self, tmp_path):
        _fresh_unsigned(tmp_path)

        result = CliRunner().invoke(
            cli, ["scan", str(tmp_path), "--fail-on-stale", "--report-only"]
        )

        assert result.exit_code == 2, result.output
        assert "mutually exclusive" in result.output


class TestScanFlagContract:
    """The flags that decide the exit code are advertised in ``--help``."""

    def test_help_names_report_only(self):
        result = CliRunner().invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        assert "--report-only" in result.output

    def test_help_marks_fail_on_stale_deprecated(self):
        result = CliRunner().invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        assert "--fail-on-stale" in result.output
        assert "Deprecated" in result.output
