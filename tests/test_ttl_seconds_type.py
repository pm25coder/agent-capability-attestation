"""Tests that a non-integer ``ttl_seconds`` is a bad *input*, not a failing one.

``ttl_seconds`` was read without a type or presence check, so a value the TTL
arithmetic cannot use reached it: ``timedelta(seconds=...)`` in
``__post_init__``, and the ``<= 0`` comparison in ``validate``. Both raised
``TypeError``, which escaped the parser as an unhandled traceback and exited
``1`` — the code a genuine validation failure uses, so a malformed document was
indistinguishable from a stale or forged one, through ``validate``,
``check-chain`` and ``check-mcp`` alike.

One shape failed the other way, and is the reason these tests name the boolean
case separately: ``bool`` subclasses ``int`` in Python, so ``ttl_seconds: true``
was read as the integer ``1`` and a one-second TTL was then *validated*. That is
a wrong answer rather than an error, and it is the harder of the two to notice.

The README already documents ``2 = malformed input``. These tests hold
``ttl_seconds`` to that contract, and hold the two boundaries the issue does
*not* move: an integer is accepted whatever its sign, because ``0`` and a
negative are ``validate``'s own "missing TTL" verdict (exit ``1``), not a
malformed document.
"""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import Attestation

#: Shapes whose JSON type is not an integer. ``True``/``False`` are here on
#: purpose: Python's ``bool`` is an ``int`` subclass, which is exactly how the
#: silent one-second TTL arose.
NON_INTEGER_TTLS = [
    pytest.param("not-an-int", "string", id="string"),
    pytest.param(None, "null", id="null"),
    pytest.param(True, "boolean", id="true"),
    pytest.param(False, "boolean", id="false"),
    pytest.param([], "array", id="array"),
    pytest.param({}, "object", id="object"),
    pytest.param(300.5, "number (300.5)", id="fractional-float"),
]


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


class TestFromDictRejectsANonIntegerTtl:
    """The choke point every document path routes through."""

    @pytest.mark.parametrize("value,named", NON_INTEGER_TTLS)
    def test_the_field_and_its_type_are_both_named(self, value, named):
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(_document(ttl_seconds=value))

        message = str(caught.value)
        assert "ttl_seconds" in message
        assert "must be an integer" in message
        assert named in message

    @pytest.mark.parametrize("value,named", NON_INTEGER_TTLS)
    def test_no_shape_escapes_as_a_type_error(self, value, named):
        """The reported defect: the parser must be total over these shapes."""
        try:
            Attestation.from_dict(_document(ttl_seconds=value))
        except ValueError:
            pass
        else:  # pragma: no cover - the assertion below is the point
            raise AssertionError(f"from_dict accepted ttl_seconds={value!r}")

    def test_a_boolean_is_not_read_as_one_second(self):
        """``true`` is the shape that produced an answer instead of an error."""
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(_document(ttl_seconds=True))

        assert "boolean" in str(caught.value)

    def test_a_direct_construction_is_rejected_too(self):
        """The check is at the point of use, so it does not depend on from_dict."""
        with pytest.raises(ValueError) as caught:
            Attestation(
                issuer="agent://planner",
                subject="agent://worker",
                capability="CAN_READ(store)",
                issued_at=datetime.now(timezone.utc),
                ttl_seconds="not-an-int",
            )

        assert "ttl_seconds" in str(caught.value)


class TestAnIntegerTtlIsStillAccepted:
    """Guard the guard: the stricter check must not move either boundary."""

    def test_an_integer_parses(self):
        attestation = Attestation.from_dict(_document(ttl_seconds=300))

        assert attestation.ttl_seconds == 300
        assert attestation.expires_at is not None

    def test_an_integral_float_is_accepted_verbatim(self):
        """``300.0`` is the integer 300, as written by a float-emitting encoder."""
        attestation = Attestation.from_dict(_document(ttl_seconds=300.0))

        assert attestation.ttl_seconds == 300.0
        assert attestation.to_dict()["ttl_seconds"] == 300.0

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

    @pytest.mark.parametrize("value,named", NON_INTEGER_TTLS)
    def test_validate_exits_two_without_a_traceback(self, tmp_path, value, named):
        path = _write(tmp_path, _document(ttl_seconds=value))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 2, result.output
        assert "Traceback" not in result.output
        assert "ttl_seconds" in result.output
        assert "must be an integer" in result.output

    @pytest.mark.parametrize("value,named", NON_INTEGER_TTLS)
    def test_check_chain_names_the_failing_hop(self, tmp_path, value, named):
        path = _write(tmp_path, [_document(ttl_seconds=value)], name="chain.json")

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 2, result.output
        assert "chain[0]" in result.output
        assert "ttl_seconds" in result.output
        assert "Traceback" not in result.output

    @pytest.mark.parametrize("value,named", NON_INTEGER_TTLS)
    def test_check_mcp_names_the_server(self, tmp_path, value, named):
        path = _write(tmp_path, _mcp_config(_document(ttl_seconds=value)), name="mcp.json")

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 2, result.output
        assert '"filesystem"' in result.output
        assert "ttl_seconds" in result.output
        assert "Traceback" not in result.output

    def test_a_well_formed_attestation_still_validates(self, tmp_path):
        """A good document is not reported as malformed by the stricter check."""
        path = _write(tmp_path, _document())

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 0, result.output


class TestScanCountsTheFileItFound:
    """The summary must describe the directory, not the files it could parse."""

    def test_a_non_integer_ttl_file_is_counted_as_unreadable(self, tmp_path):
        _write(tmp_path, _document(), name="ok.attestation.json")
        _write(
            tmp_path,
            _document(ttl_seconds="not-an-int"),
            name="badttl.attestation.json",
        )

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output
        assert "2 attestations scanned" in result.output
        assert "1 unreadable" in result.output
        assert "ttl_seconds" in result.output

    def test_the_json_document_lists_it_too(self, tmp_path):
        """A JSON consumer must see the file, not a quietly smaller list."""
        _write(tmp_path, _document(), name="ok.attestation.json")
        _write(tmp_path, _document(ttl_seconds=True), name="bool.attestation.json")

        result = _runner().invoke(cli, ["scan", str(tmp_path), "--json-output"])

        assert result.exit_code == 1, result.output
        payload = json.loads(result.stdout)
        assert len(payload) == 2
        assert any(entry.get("unreadable") for entry in payload)
        listed = " ".join(str(entry.get("file")) for entry in payload)
        assert "bool.attestation.json" in listed
