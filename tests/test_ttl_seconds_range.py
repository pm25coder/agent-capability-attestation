"""Tests that a ``ttl_seconds`` the deadline arithmetic cannot represent is a bad
*input*, not a failing attestation.

#48 type-checked this field, and the check it added is on the **type**: it
accepts ``1e30`` and ``10**30``, because both are integral (``float.is_integer()``
is ``True``). A type-correct integer still has a magnitude that
``issued_at + timedelta(seconds=...)`` cannot represent — and the failure lands in
that arithmetic, *after* the guard, exactly where #48's own analysis predicted the
residue would fall. It escaped as an unhandled ``OverflowError`` with exit ``1``,
the code a genuinely *stale* attestation uses, so a malformed document could not
be told apart from an expired one through ``validate``, ``check-chain`` and
``check-mcp`` alike.

Two distinct overflows are covered, because two different operations fail:
``timedelta(seconds=...)`` rejects an int too large for a C int (``1e30``), and the
``datetime`` sum rejects a result outside years ``1..9999`` — which ``999999999999``
reaches comfortably inside ``timedelta``'s own range. That second shape is why the
bound cannot be a constant ceiling on the number: whether a value is
representable depends on ``issued_at`` as well, and the same ``86400`` is fine from
today's clock and out of range from ``9999-12-31``.

The README documents ``2 = malformed input``; these tests hold the field to it, and
hold the boundaries the change does *not* move — a large but representable TTL, and
``0``/negative, which remain ``validate``'s own "missing TTL" verdict (exit ``1``).
"""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import Attestation, AttestationValidator

#: Values whose JSON type *is* an integer (or an integral float), and whose
#: magnitude the deadline arithmetic cannot represent.
UNREPRESENTABLE_TTLS = [
    pytest.param(1e30, id="float-1e30"),
    pytest.param(10**30, id="int-10-to-the-30"),
    pytest.param(999999999999, id="int-inside-timedelta-but-past-datetime"),
]

#: The largest legal datetime, used to show that the bound follows the sum.
LATEST_ISSUED_AT = "9999-12-31T23:59:59+00:00"


def _runner():
    """A ``CliRunner`` whose ``stdout`` cannot be polluted by stderr."""
    if "mix_stderr" in inspect.signature(CliRunner.__init__).parameters:
        return CliRunner(mix_stderr=False)
    return CliRunner()


def _write(tmp_path, payload, name="attestation.json"):
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return path


def _document(**extra) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    document = {
        "issuer": "agent://planner",
        "subject": "agent://worker",
        "capability": "CAN_READ(store)",
        "issued_at": (now - timedelta(seconds=5)).isoformat(),
        "ttl_seconds": 300,
    }
    document.update(extra)
    return document


def _mcp_config(attestation) -> dict:
    return {
        "mcpServers": {
            "filesystem": {"command": "npx", "capabilityAttestation": attestation}
        }
    }


class TestFromDictRejectsAnUnrepresentableTtl:
    """The choke point every document path routes through."""

    @pytest.mark.parametrize("value", UNREPRESENTABLE_TTLS)
    def test_the_field_and_the_reason_are_both_named(self, value):
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(_document(ttl_seconds=value))

        message = str(caught.value)
        assert "ttl_seconds" in message
        assert "out of range" in message

    @pytest.mark.parametrize("value", UNREPRESENTABLE_TTLS)
    def test_no_shape_escapes_as_an_overflow(self, value):
        """The reported defect: the parser must be total over these shapes."""
        try:
            Attestation.from_dict(_document(ttl_seconds=value))
        except ValueError:
            pass
        else:  # pragma: no cover - the assertion below is the point
            raise AssertionError(f"from_dict accepted ttl_seconds={value!r}")

    @pytest.mark.parametrize("value", UNREPRESENTABLE_TTLS)
    def test_a_direct_construction_is_rejected_too(self, value):
        """The check is at the point of use, so it does not depend on from_dict."""
        with pytest.raises(ValueError):
            Attestation(
                issuer="agent://planner",
                subject="agent://worker",
                capability="CAN_READ(store)",
                issued_at=datetime.now(timezone.utc),
                ttl_seconds=value,
            )

    def test_a_declared_expires_at_does_not_excuse_the_ttl(self):
        """The deadline is computed even when ``expires_at`` is declared.

        ``validate`` recomputes ``issued_at + ttl_seconds`` for *every*
        attestation, declared expiry or not, so an unusable TTL has to fail at
        construction — where every caller maps it to exit 2 — rather than
        mid-validation, on the one path where the model is otherwise valid.
        """
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(
                _document(ttl_seconds=1e30, expires_at="2099-01-01T00:00:00+00:00")
            )

        assert "out of range" in str(caught.value)

    def test_the_bound_is_on_the_sum_not_on_the_number(self):
        """A tiny TTL is unrepresentable from a legal but late ``issued_at``.

        This is what rules out a constant ceiling at ``timedelta.max``: ``1``
        second is representable, ``9999-12-31T23:59:59`` is a legal ``issued_at``,
        and their sum is not a datetime.
        """
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(
                _document(issued_at=LATEST_ISSUED_AT, ttl_seconds=1)
            )

        assert "ttl_seconds 1 is out of range" in str(caught.value)

    def test_a_late_clock_with_a_representable_sum_is_still_fine(self):
        """Control: the check must not reject a representable sum."""
        attestation = Attestation.from_dict(
            _document(issued_at="9999-12-31T22:00:00+00:00", ttl_seconds=3600)
        )

        assert attestation.expires_at == datetime(
            9999, 12, 31, 23, 0, tzinfo=timezone.utc
        )


class TestARepresentableTtlIsStillAccepted:
    """Guard the guard: the stricter check must not move the existing boundaries."""

    def test_an_ordinary_integer_still_parses(self):
        attestation = Attestation.from_dict(_document(ttl_seconds=300))

        assert attestation.ttl_seconds == 300
        assert attestation.expires_at == attestation.issued_at + timedelta(seconds=300)

    def test_a_large_but_representable_ttl_still_validates(self, tmp_path):
        """31.7 years of TTL is representable, and is not this change's business."""
        path = _write(tmp_path, _document(ttl_seconds=999_999_999))

        result = CliRunner().invoke(
            cli, ["validate", "--max-ttl", "1000000000", str(path)]
        )

        assert result.exit_code == 0, result.output

    @pytest.mark.parametrize("value", [0, -1])
    def test_zero_and_negative_are_values_not_malformed_documents(self, tmp_path, value):
        """``0`` and a negative reach validate's ``<= 0`` branch — exit 1, not 2."""
        attestation = Attestation.from_dict(_document(ttl_seconds=value))
        assert attestation.ttl_seconds == value

        path = _write(tmp_path, _document(ttl_seconds=value))
        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 1, result.output
        assert "Missing TTL" in result.output


class TestTheCliReportsItAsMalformedInput:
    """Exit 2 with no traceback, the way a missing ``issued_at`` reports."""

    @pytest.mark.parametrize("value", UNREPRESENTABLE_TTLS)
    def test_validate_exits_two_without_a_traceback(self, tmp_path, value):
        path = _write(tmp_path, _document(ttl_seconds=value))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 2, result.output
        assert "Traceback" not in result.output
        assert "OverflowError" not in result.output
        assert "ttl_seconds" in result.output
        assert "out of range" in result.output

    @pytest.mark.parametrize("value", UNREPRESENTABLE_TTLS)
    def test_check_chain_names_the_failing_hop(self, tmp_path, value):
        hop0 = _document()
        hop1 = _document(
            issuer="agent://worker",
            subject="agent://orchestrator",
            ttl_seconds=value,
        )
        path = _write(tmp_path, [hop0, hop1], name="chain.json")

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 2, result.output
        assert "chain[1]" in result.output
        assert "ttl_seconds" in result.output
        assert "Traceback" not in result.output

    @pytest.mark.parametrize("value", UNREPRESENTABLE_TTLS)
    def test_check_mcp_names_the_server(self, tmp_path, value):
        path = _write(
            tmp_path, _mcp_config(_document(ttl_seconds=value)), name="mcp.json"
        )

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 2, result.output
        assert '"filesystem"' in result.output
        assert "ttl_seconds" in result.output
        assert "Traceback" not in result.output


class TestScanCountsTheFileItFound:
    """The summary must describe the directory, not the files it could parse."""

    def test_an_unrepresentable_ttl_file_is_counted_as_unreadable(self, tmp_path):
        _write(tmp_path, _document(), name="ok.attestation.json")
        _write(
            tmp_path,
            _document(ttl_seconds=1e30),
            name="hugettl.attestation.json",
        )

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output
        assert "2 attestations scanned" in result.output
        assert "1 unreadable" in result.output
        assert "ttl_seconds" in result.output


class TestAnUnusablePolicyCeilingIsNotACeiling:
    """The same expression appears a third time, on the operator's ``max_ttl``.

    ``--max-ttl`` is compared as a deadline (``issued_at + timedelta(seconds=
    max_ttl)``), so an operator value the arithmetic cannot represent used to
    crash ``validate`` with the same ``OverflowError`` and exit ``1``. A ceiling
    nothing representable can exceed is not a ceiling, so the comparison is
    vacuous rather than fatal.
    """

    @pytest.mark.parametrize(
        "ceiling",
        [
            pytest.param("99999999999999999", id="past-timedelta"),
            pytest.param("86399999913600", id="inside-timedelta-past-datetime"),
        ],
    )
    def test_an_unrepresentable_ceiling_does_not_crash(self, tmp_path, ceiling):
        path = _write(tmp_path, _document())

        result = CliRunner().invoke(cli, ["validate", "--max-ttl", ceiling, str(path)])

        assert result.exit_code == 0, result.output
        assert "Traceback" not in result.output
        assert "OverflowError" not in result.output

    def test_the_ceiling_still_rejects_when_it_is_representable(self, tmp_path):
        """Control arm: the skip must not disable the ceiling itself."""
        path = _write(tmp_path, _document(ttl_seconds=600))

        result = CliRunner().invoke(cli, ["validate", "--max-ttl", "300", str(path)])

        assert result.exit_code == 1, result.output
        assert "exceeds max 300s" in result.output


class TestValidateRecomputesTheTtlWithoutRaising:
    """The recomputation inside ``validate`` is guarded, not only construction.

    Construction computes ``issued_at + ttl_seconds`` unconditionally, so every
    public path is already covered and this test reaches the arithmetic the one
    other way there is: ``Attestation`` is a *mutable* dataclass, so a value can
    be re-pointed after construction, and ``validate`` recomputes the sum for
    every attestation it is handed. ``validate`` promises a result rather than a
    traceback, so the malformed value must surface as a named error and not as
    the raw ``OverflowError`` #53 reports.
    """

    def test_a_repointed_ttl_is_reported_not_raised(self):
        attestation = Attestation.from_dict(_document(ttl_seconds=300))
        attestation.ttl_seconds = 10**30

        result = AttestationValidator(now=datetime.now(timezone.utc)).validate(
            attestation
        )

        assert result.is_valid is False
        assert any(
            "ttl_seconds" in error and "out of range" in error
            for error in result.errors
        ), result.errors

    def test_the_repointee_still_reaches_the_arithmetic(self):
        """Guard the guard: the re-pointed value must actually be the one used.

        A representable re-point is accepted, which is what proves the value —
        and not the construction-time one — is what ``validate`` recomputes.
        """
        attestation = Attestation.from_dict(_document(ttl_seconds=300))
        attestation.ttl_seconds = 600
        attestation.expires_at = attestation.issued_at + timedelta(seconds=600)

        result = AttestationValidator(
            max_ttl=1000, now=datetime.now(timezone.utc)
        ).validate(attestation)

        assert result.is_valid is True, result.errors

