"""Tests that a declared ``expires_at`` can shorten an attestation's life but not extend it.

``Attestation.expires_at`` is attacker-controlled: it is one of the values an editor of an
attestation file chooses. ``validate()`` used the declared value as *the* deadline, so a
1-second TTL carrying ``expires_at: 2099`` reported ``✓ VALID`` and exited ``0`` — and no
value of ``--max-ttl`` closed it, because ``max_ttl`` is compared against ``ttl_seconds``,
which no longer decided expiry once the field was present.

Both directions are pinned here, because a bound that only hardens the long-expiry case
regresses #11 (an attestation that declares itself expired must still be honoured): the
extending direction is an error, the shortening direction is not.

What this fix deliberately does *not* do is make ``max_ttl`` binding — that is #18, its
contract is pinned by ``test_max_ttl_remains_advisory`` in ``test_future_issued_at.py``,
and the bound here is the TTL-derived deadline rather than the policy ceiling for exactly
that reason (see ``TestMaxTtlStaysAdvisory``).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import Attestation, AttestationValidator

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
NINETY_NINE = datetime(2099, 1, 1, tzinfo=timezone.utc)


def _validator(max_ttl=300, **kwargs):
    return AttestationValidator(now=NOW, max_ttl=max_ttl, **kwargs)


def _extending(ttl_seconds=1, age=timedelta(days=30)):
    """The issue's fixture: a short TTL stretched by a declared far-future expiry."""
    return Attestation(
        "agent://planner",
        "agent://attacker",
        "CAN_DELETE_ALL(state)",
        NOW - age,
        ttl_seconds,
        expires_at=NINETY_NINE,
    )


class TestTheBound:
    def test_declared_expires_at_cannot_extend_the_ttl_deadline(self):
        """The reported defect: expired by its own TTL, revived by a declared expiry."""
        result = _validator().validate(_extending())

        assert not result.is_valid
        assert any("outlives" in e for e in result.errors), result.errors

    def test_the_verdict_is_stale_not_merely_invalid(self):
        """Staleness is recomputed against the TTL deadline, so the reading is truthful:
        the attestation is not 'invalid for an unrelated reason', it is expired."""
        result = _validator().validate(_extending())

        assert result.is_stale
        assert result.stale_by_seconds is not None

    def test_an_extension_is_rejected_even_when_the_ttl_has_not_elapsed(self):
        """The bound is about the *declaration*, not about the clock: a live attestation
        whose author claims a year of life it was not granted is still a lie."""
        att = Attestation(
            "i", "s", "CAN_READ(store)", NOW, 60, expires_at=NOW + timedelta(days=365)
        )

        result = _validator().validate(att)

        assert not result.is_valid
        assert not result.is_stale

    def test_an_extension_of_one_second_is_rejected(self):
        """The bound is exact, with no tolerance band.

        ``issued_at`` and ``expires_at`` are serialized at microsecond precision by
        ``to_dict()``, so a machine-written pair is exactly equal and any strict excess is
        a real disagreement. A tolerance would have to come from ``max_skew_seconds``,
        which is operator-controlled -- widening the clock-skew window must not widen
        what a declaration may claim.
        """
        att = Attestation(
            "i", "s", "CAN_READ(store)", NOW, 60, expires_at=NOW + timedelta(seconds=61)
        )

        result = _validator().validate(att)

        assert not result.is_valid

    def test_a_declared_expiry_may_still_shorten(self):
        """#11 must keep passing: a declared expiry that is earlier still wins."""
        att = Attestation(
            "i", "s", "CAN_READ(store)", NOW - timedelta(days=30), 300,
            expires_at=NOW - timedelta(days=30) + timedelta(seconds=1),
        )

        result = _validator().validate(att)

        assert not result.is_valid
        assert result.is_stale

    def test_a_declared_expiry_in_the_past_is_honoured(self):
        """The #22 reading, unchanged: a live TTL does not launder a dead declaration."""
        att = Attestation(
            "i", "s", "CAN_READ(store)", NOW, 31536000,
            expires_at=NOW - timedelta(hours=1),
        )

        result = _validator().validate(att)

        assert not result.is_valid
        assert result.is_stale


class TestControls:
    def test_a_consistent_declared_expiry_still_passes(self):
        att = Attestation("i", "s", "CAN_READ(store)", NOW, 300)

        result = _validator().validate(att)

        assert result.is_valid
        assert result.errors == []

    def test_an_explicit_consistent_expiry_still_passes(self):
        att = Attestation(
            "i", "s", "CAN_READ(store)", NOW, 300,
            expires_at=NOW + timedelta(seconds=300),
        )

        result = _validator().validate(att)

        assert result.is_valid
        assert result.errors == []

    def test_the_extension_error_does_not_also_claim_to_honour_the_declaration(self):
        """The old warning said the tool was honouring the value it now rejects; the two
        must not both appear, or the output would contradict itself."""
        result = _validator().validate(_extending())

        assert not any("honoring" in w for w in result.warnings), result.warnings


class TestMaxTtlStaysAdvisory:
    """The bound is the TTL deadline, not the policy ceiling (#18 stays open)."""

    def test_a_long_ttl_with_no_declared_expiry_still_only_warns(self):
        att = Attestation("i", "s", "CAN_READ(store)", NOW, 31536000)

        result = _validator(max_ttl=300).validate(att)

        assert result.is_valid
        assert any("exceeds max" in w for w in result.warnings)

    def test_a_consistent_declaration_longer_than_max_ttl_still_only_warns(self):
        """An honest attestation whose own expiry matches its own TTL is consistent, so
        this fix has no opinion about it; making ``max_ttl`` bind it is #18's change."""
        att = Attestation(
            "i", "s", "CAN_READ(store)", NOW, 86_400,
            expires_at=NOW + timedelta(seconds=86_400),
        )

        result = _validator(max_ttl=300).validate(att)

        assert result.is_valid
        assert any("exceeds max" in w for w in result.warnings)


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return path


def _override_document():
    """The CLI runs on the wall clock, so this fixture is built from it rather than
    from the frozen ``NOW`` the library tests use."""
    now = datetime.now(timezone.utc)
    return {
        "issuer": "agent://planner",
        "subject": "agent://attacker",
        "capability": "CAN_DELETE_ALL(state)",
        "issued_at": (now - timedelta(days=30)).isoformat(),
        "ttl_seconds": 1,
        "expires_at": "2099-01-01T00:00:00+00:00",
    }


class TestThroughTheCli:
    def test_validate_exits_one_and_names_the_bound(self, tmp_path):
        path = _write(tmp_path, "override.attestation.json", _override_document())

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 1, result.output
        assert "outlives" in result.output

    def test_the_strictest_max_ttl_is_no_longer_needed_to_close_it(self, tmp_path):
        """The issue's step 3: ``--max-ttl 1`` used to be the only knob that could have
        helped and it did not; the default now fails closed without it."""
        path = _write(tmp_path, "override.attestation.json", _override_document())

        result = CliRunner().invoke(cli, ["validate", str(path), "--max-ttl", "1"])

        assert result.exit_code == 1, result.output

    def test_json_output_reports_errors_not_only_warnings(self, tmp_path):
        """A programmatic consumer gates on ``errors``/``is_valid``, so the verdict must
        not be a warnings-only reading."""
        path = _write(tmp_path, "override.attestation.json", _override_document())

        result = CliRunner().invoke(cli, ["validate", str(path), "--json-output"])

        payload = json.loads(result.stdout)
        assert payload["is_valid"] is False
        assert payload["is_stale"] is True
        assert any("outlives" in e for e in payload["errors"])

    def test_a_chain_hop_may_not_revive_itself(self, tmp_path):
        """The issue's step 5, isolated to one hop: the parent is live, so nothing else
        can account for the failure."""
        chain = [
            {
                "issuer": "agent://root",
                "subject": "agent://planner",
                "capability": "CAN_READ(store)",
                "issued_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": 300,
            },
            {
                "issuer": "agent://planner",
                "subject": "agent://attacker",
                "capability": "CAN_READ(store)",
                "issued_at": (
                    datetime.now(timezone.utc) - timedelta(days=30)
                ).isoformat(),
                "ttl_seconds": 1,
                "expires_at": "2099-01-01T00:00:00+00:00",
            },
        ]
        path = _write(tmp_path, "chain.json", chain)

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 1, result.output
        hops = [line for line in result.output.splitlines() if line.startswith("[Hop ")]
        assert len(hops) == 2, result.output
        assert "[Hop 0] ✓ VALID" in hops[0], result.output
        assert "[Hop 1] ✗" in hops[1], result.output
