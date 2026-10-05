"""Tests that a non-string identity field is bad *input*, not an invalid attestation.

``issuer``, ``subject`` and ``capability`` were read with no type check, and each
is used as a string somewhere. The reported failure is ``check-chain``: hop *N*'s
``capability`` reaches ``_scope_is_subscope``, whose first acts are
``parent.endswith("*")`` and ``child.startswith(...)``, so a non-string value
escaped as an unhandled ``AttributeError`` and exited ``1`` — the code a *stale
hop* uses, so a malformed document was indistinguishable from an expired one.

The quieter half is the one these tests name explicitly: through ``validate`` a
non-string ``issuer``/``subject``/``capability`` produced ``✓ VALID`` and exit
``0`` — a wrong answer with no error at all. That is the ``ttl_seconds: true``
shape #50 fixed, for the fields #50 did not reach.

There is no value of these fields that yields a correct verdict, so the check is
on the value itself and the document is malformed *input* (exit ``2``), which is
what the README's ``2 = malformed input`` line already promises. ``state_hash``
and ``provenance`` are the same class (the README shows a string and an array of
agent URIs respectively) and are covered by the same construction-time guard.

The tests also hold the boundaries this change deliberately does **not** move:
an empty string is a string; a ``null``/absent ``state_hash`` is "absent"; and a
falsy ``expires_at`` stays deferred to its own discussion, as issue #51 asks.
"""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import Attestation

#: Shapes whose JSON type is not a string. ``True`` is here because the CLI
#: prints it as ``True`` and a reader would not otherwise notice it is not text.
NON_STRING_VALUES = [
    pytest.param(123, "number", id="number"),
    pytest.param(12.5, "number", id="float"),
    pytest.param(True, "boolean", id="true"),
    pytest.param(False, "boolean", id="false"),
    pytest.param(None, "null", id="null"),
    pytest.param([], "array", id="array"),
    pytest.param({}, "object", id="object"),
]

#: The identity fields the schema documents as strings.
IDENTITY_FIELDS = ["issuer", "subject", "capability"]

#: Shapes a ``state_hash`` may not take. ``None`` is excluded on purpose: the
#: field is ``Optional[str]``, so ``null`` is its documented "absent" form.
NON_STRING_STATE_HASHES = [
    pytest.param(123, "number", id="number"),
    pytest.param(True, "boolean", id="true"),
    pytest.param([], "array", id="array"),
    pytest.param({}, "object", id="object"),
]

#: Shapes a ``provenance`` may not take. ``[]`` is excluded: the field is a
#: list, so an empty array is a valid (empty) value, not a wrong type.
NON_LIST_PROVENANCES = [
    pytest.param(123, "number", id="number"),
    pytest.param(True, "boolean", id="true"),
    pytest.param(None, "null", id="null"),
    pytest.param({}, "object", id="object"),
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
    """A fresh, well-formed attestation; ``extra`` overrides one field."""
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


def _two_hop_chain(bad_capability) -> list:
    """The chain from the issue: hop 1's capability is not a string."""
    hop0 = _document()
    hop1 = _document(issuer="agent://worker", subject="agent://orchestrator")
    hop1["capability"] = bad_capability
    return [hop0, hop1]


def _mcp_config(attestation) -> dict:
    return {
        "mcpServers": {
            "filesystem": {"command": "npx", "capabilityAttestation": attestation}
        }
    }


class TestFromDictRejectsANonStringIdentityField:
    """The choke point every document path routes through."""

    @pytest.mark.parametrize("field", IDENTITY_FIELDS)
    @pytest.mark.parametrize("value,named", NON_STRING_VALUES)
    def test_the_field_and_its_type_are_both_named(self, field, value, named):
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(_document(**{field: value}))

        message = str(caught.value)
        assert field in message
        assert "must be a string" in message
        assert named in message

    @pytest.mark.parametrize("field", IDENTITY_FIELDS)
    @pytest.mark.parametrize("value,named", NON_STRING_VALUES)
    def test_no_shape_escapes_as_an_attribute_error(self, field, value, named):
        """The reported defect: the parser must be total over these shapes."""
        try:
            Attestation.from_dict(_document(**{field: value}))
        except ValueError:
            pass
        else:  # pragma: no cover - the assertion below is the point
            raise AssertionError(f"from_dict accepted {field}={value!r}")

    @pytest.mark.parametrize("value,named", NON_STRING_VALUES)
    def test_a_direct_construction_is_rejected_too(self, value, named):
        """The check is at the point of use, so it does not depend on from_dict."""
        with pytest.raises(ValueError) as caught:
            Attestation(
                issuer="agent://planner",
                subject="agent://worker",
                capability=value,
                issued_at=datetime.now(timezone.utc),
                ttl_seconds=300,
            )

        assert "capability" in str(caught.value)


class TestTheQuieterVariantsAreCaughtAsWell:
    """``validate`` used to answer ``✓ VALID``/exit 0 for these."""

    @pytest.mark.parametrize("field", IDENTITY_FIELDS)
    def test_validate_exits_two_without_a_traceback(self, tmp_path, field):
        path = _write(tmp_path, _document(**{field: []}))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 2, result.output
        assert "Traceback" not in result.output
        assert field in result.output
        assert "VALID" not in result.output

    def test_validate_a_non_string_subject_is_not_reported_valid(self, tmp_path):
        """The exact row from the issue's table."""
        path = _write(tmp_path, _document(subject=[]))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 2, result.output
        assert "subject" in result.output


class TestCheckChainNamesTheFailingHop:
    """The chain element is the level a malformed document hides at."""

    @pytest.mark.parametrize("value,named", NON_STRING_VALUES)
    def test_a_non_string_capability_in_hop_one(self, tmp_path, value, named):
        path = _write(tmp_path, _two_hop_chain(value), name="chain.json")

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 2, result.output
        assert "chain[1]" in result.output
        assert "capability" in result.output
        assert "Traceback" not in result.output

    def test_a_non_string_issuer_is_caught_before_the_dict_lookup(self, tmp_path):
        """An unhashable issuer used to reach the trusted-key lookup unchecked."""
        path = _write(tmp_path, _two_hop_chain("CAN_READ(store)"), name="chain.json")
        document = json.loads(path.read_text())
        document[1]["issuer"] = []
        path.write_text(json.dumps(document))

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 2, result.output
        assert "chain[1]" in result.output
        assert "issuer" in result.output
        assert "Traceback" not in result.output

    def test_the_issue_reproduction_no_longer_tracebacks(self, tmp_path):
        """The verbatim chain from issue #51: hop 1's capability is ``[]``."""
        chain = [
            {"issuer": "agent://planner", "subject": "agent://worker",
             "capability": "CAN_READ(store)",
             "issued_at": "2026-10-05T09:00:00+00:00", "ttl_seconds": 300},
            {"issuer": "agent://worker", "subject": "agent://orchestrator",
             "capability": [],
             "issued_at": "2026-10-05T09:00:00+00:00", "ttl_seconds": 300},
        ]
        path = _write(tmp_path, chain, name="chain.json")

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 2, result.output
        assert "AttributeError" not in result.output
        assert "Traceback" not in result.output


class TestCheckMcpNamesTheServer:
    def test_a_non_string_capability_in_an_mcp_attestation(self, tmp_path):
        path = _write(tmp_path, _mcp_config(_document(capability=[])), name="mcp.json")

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 2, result.output
        assert '"filesystem"' in result.output
        assert "capability" in result.output
        assert "Traceback" not in result.output


class TestScanReportsTheFileItFound:
    """A malformed file must not be reported as a valid one."""

    def test_a_malformed_file_is_not_counted_as_valid(self, tmp_path):
        _write(tmp_path, _document(), name="ok.attestation.json")
        _write(tmp_path, _document(capability=[]), name="bad.attestation.json")

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output
        assert "2 attestations scanned" in result.output
        assert "1 unreadable" in result.output
        assert "capability" in result.output

    def test_the_json_document_lists_it_too(self, tmp_path):
        _write(tmp_path, _document(), name="ok.attestation.json")
        _write(tmp_path, _document(issuer=123), name="bad.attestation.json")

        result = _runner().invoke(cli, ["scan", str(tmp_path), "--json-output"])

        assert result.exit_code == 1, result.output
        payload = json.loads(result.stdout)
        assert len(payload) == 2
        assert any(entry.get("unreadable") for entry in payload)


class TestTheOptionalFieldsFollowTheSameRule:
    """``state_hash`` a string, ``provenance`` a list of strings."""

    @pytest.mark.parametrize("value,named", NON_STRING_STATE_HASHES)
    def test_a_present_state_hash_must_be_a_string(self, value, named):
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(_document(state_hash=value))

        assert "state_hash" in str(caught.value)
        assert named in str(caught.value)

    @pytest.mark.parametrize("value,named", NON_LIST_PROVENANCES)
    def test_provenance_must_be_a_list(self, value, named):
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(_document(provenance=value))

        assert "provenance" in str(caught.value)
        assert named in str(caught.value)

    def test_a_list_of_non_strings_is_rejected_too(self):
        """The element type, not just the container, is what the schema fixes."""
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(_document(provenance=["agent://a", 123]))

        assert "provenance" in str(caught.value)
        assert "number" in str(caught.value)

    def test_an_absent_state_hash_is_still_allowed(self):
        """``None`` is how "absent" reaches the model; it is not a wrong type."""
        attestation = Attestation.from_dict(_document())

        assert attestation.state_hash is None

    def test_an_explicit_null_state_hash_is_still_allowed(self):
        attestation = Attestation.from_dict(_document(state_hash=None))

        assert attestation.state_hash is None

    def test_an_empty_provenance_list_is_still_allowed(self):
        attestation = Attestation.from_dict(_document(provenance=[]))

        assert attestation.provenance == []


class TestTheStricterCheckDoesNotMoveTheBoundaries:
    """Guard the guard: a good document is not caught by the new checks."""

    def test_a_well_formed_attestation_still_validates(self, tmp_path):
        path = _write(tmp_path, _document())

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 0, result.output

    def test_a_well_formed_chain_still_validates(self, tmp_path):
        path = _write(
            tmp_path,
            [_document(), _document(issuer="agent://worker",
                                    subject="agent://orchestrator")],
            name="chain.json",
        )

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 0, result.output

    def test_an_empty_string_is_still_a_string(self):
        """The rule is the type; ``""`` is text and is left to a separate rule."""
        attestation = Attestation.from_dict(_document(issuer=""))

        assert attestation.issuer == ""

    @pytest.mark.parametrize("value", [[], {}, "", 0, False])
    def test_a_falsy_expires_at_stays_deferred(self, tmp_path, value):
        """Issue #51 puts this on its own track; this change must not touch it."""
        path = _write(tmp_path, _document(expires_at=value))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        # Still silently dropped for the TTL-derived deadline, as reported.
        assert result.exit_code == 0, result.output

    @pytest.mark.parametrize("value", [0, -1])
    def test_a_non_positive_ttl_is_still_an_invalid_document(self, tmp_path, value):
        """``ttl_seconds <= 0`` is validate's own verdict (exit 1), not exit 2."""
        path = _write(tmp_path, _document(ttl_seconds=value))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 1, result.output
        assert "Missing TTL" in result.output
