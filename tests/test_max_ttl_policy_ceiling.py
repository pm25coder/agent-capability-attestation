"""Tests that ``max_ttl`` is a policy ceiling that is enforced, not narrated.

``AttestationValidator(max_ttl=...)`` appended a warning and left ``is_valid``
``True``, so an attestation declaring ``ttl_seconds: 315360000`` (ten years) was
reported ``✓ VALID`` under a 300-second ceiling and ``aca validate`` exited ``0``.
The status line and the warning contradicted each other, and the CI recipe in the
project README — ``aca scan ./agents/ --fail-on-stale`` — passed a policy
violation. A missing TTL was fail-closed; the TTL *ceiling* was the one TTL rule
that was not, which is the more dangerous half: raising a number in the file is
all an attacker has to do.

The ceiling is measured against the deadline the validator actually uses — the
declared ``expires_at`` when there is one, otherwise ``issued_at + ttl_seconds`` —
rather than against the ``ttl_seconds`` field, because a declared expiry that
shortens a long TTL is a separate, deliberate rule, and rejecting such an
attestation would undo it.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import Attestation, AttestationValidator

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
TEN_YEARS = 315_360_000


def _document(ttl_seconds=TEN_YEARS, **extra):
    """The issue's own reproduction fixture, built on the wall clock.

    The CLI validates against ``datetime.now()``, so the fixture is built from it
    rather than from the frozen ``NOW`` the library tests use — otherwise the file
    would also be a day stale, and the ceiling would not be what is under test.
    """
    data = {
        "issuer": "agent://planner",
        "subject": "agent://worker",
        "capability": "CAN_WRITE(root)",
        "issued_at": (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(),
        "ttl_seconds": ttl_seconds,
    }
    data.update(extra)
    return data


def _write(tmp_path, payload, name="huge_ttl.attestation.json"):
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return path


def _validate(ttl_seconds, max_ttl=300):
    att = Attestation(
        "agent://planner", "agent://worker", "CAN_WRITE(root)", NOW, ttl_seconds
    )
    return AttestationValidator(now=NOW, max_ttl=max_ttl).validate(att)


class TestTheLibraryCeiling:
    def test_a_ten_year_ttl_under_a_300s_ceiling_is_invalid(self):
        result = _validate(TEN_YEARS)

        assert not result.is_valid
        assert any("exceeds max 300s" in e for e in result.errors), result.errors

    def test_the_rejection_is_not_reported_as_staleness(self):
        """The attestation is fresh; it is the ceiling it breaks, not its age."""
        result = _validate(TEN_YEARS)

        assert not result.is_stale
        assert result.stale_by_seconds is None

    def test_the_ceiling_is_the_operators_number(self):
        assert _validate(TEN_YEARS, max_ttl=TEN_YEARS).is_valid
        assert not _validate(600, max_ttl=300).is_valid
        assert _validate(300, max_ttl=300).is_valid

    def test_max_ttl_zero_means_no_life_is_acceptable(self):
        """``--max-ttl 0`` is expressible (it used to be a blanket pass)."""
        assert not _validate(1, max_ttl=0).is_valid

    def test_a_declared_expiry_inside_the_ceiling_keeps_it_valid(self):
        """The ceiling bounds the life, not the ``ttl_seconds`` field.

        An attestation whose own declared expiry kills it in ten seconds is inside a
        300-second ceiling however large its TTL field is; measuring the field instead
        would reject a live attestation.
        """
        att = Attestation(
            "agent://planner",
            "agent://worker",
            "CAN_WRITE(root)",
            NOW,
            TEN_YEARS,
            expires_at=NOW + timedelta(seconds=10),
        )

        result = AttestationValidator(now=NOW, max_ttl=300).validate(att)

        assert result.is_valid

    def test_enforce_max_ttl_false_restores_the_warning(self):
        """The library escape hatch the CLI flag is built on."""
        att = Attestation(
            "agent://planner", "agent://worker", "CAN_WRITE(root)", NOW, TEN_YEARS
        )

        result = AttestationValidator(
            now=NOW, max_ttl=300, enforce_max_ttl=False
        ).validate(att)

        assert result.is_valid
        assert any("exceeds max 300s" in w for w in result.warnings)


class TestTheCliCeiling:
    def test_validate_exits_one_on_an_over_ceiling_ttl(self, tmp_path):
        path = _write(tmp_path, _document())

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 1, result.output
        assert "✗ INVALID" in result.output
        assert "✓ VALID" not in result.output
        assert "exceeds max 300s" in result.output

    def test_json_output_carries_the_error(self, tmp_path):
        path = _write(tmp_path, _document())

        result = CliRunner().invoke(cli, ["validate", str(path), "--json-output"])

        payload = json.loads(result.output)
        assert payload["is_valid"] is False
        assert payload["is_stale"] is False
        assert any("exceeds max" in e for e in payload["errors"])

    def test_the_documented_scan_gate_stops_passing_a_ceiling_violation(self, tmp_path):
        """The README's CI recipe must fail on this file."""
        _write(tmp_path, _document())

        result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--fail-on-stale"])

        assert result.exit_code == 1, result.output
        assert "1 attestations scanned, 1 invalid (0 stale)" in result.output

    def test_warn_on_exceeding_max_ttl_restores_the_advisory_behaviour(self, tmp_path):
        path = _write(tmp_path, _document())

        result = CliRunner().invoke(
            cli, ["validate", str(path), "--warn-on-exceeding-max-ttl"]
        )

        assert result.exit_code == 0, result.output
        assert "WARN: TTL 315360000s exceeds max 300s" in result.output

    def test_the_opt_in_keeps_the_json_error_list_empty(self, tmp_path):
        path = _write(tmp_path, _document())

        result = CliRunner().invoke(
            cli,
            ["validate", str(path), "--warn-on-exceeding-max-ttl", "--json-output"],
        )

        payload = json.loads(result.output)
        assert payload["is_valid"] is True
        assert payload["errors"] == []
        assert any("exceeds max" in w for w in payload["warnings"])

    def test_check_chain_applies_the_ceiling_per_hop(self, tmp_path):
        chain = [
            dict(
                _document(),
                issuer="agent://a",
                subject="agent://b",
                capability="CAN_WRITE(store:*)",
            ),
            dict(
                _document(),
                issuer="agent://b",
                subject="agent://c",
                capability="CAN_WRITE(store:partition_1)",
            ),
        ]
        path = _write(tmp_path, chain, name="chain.json")

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 1, result.output
        assert "exceeds max 300s" in result.output
