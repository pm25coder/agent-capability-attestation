"""Tests that a malformed attestation payload is a bad *input*, not a failing one.

``Attestation.from_dict`` read ``issuer``, ``subject``, ``capability`` and
``issued_at`` by subscript with no validation, so a structurally invalid
document raised ``KeyError`` or ``TypeError`` out of the parser. Two of the three
CLI entry points called it outside any ``try``, and the third — ``check-mcp`` —
guarded every level of its walk except the attestation element itself, so a
malformed document escaped as an unhandled traceback. The process then exited
``1``: the exact code a genuine validation failure uses, so a broken file was
indistinguishable from a stale or forged one. The README already documents
``2 = malformed input``; these tests hold the attestation payload to that
contract.

``tests/test_malformed_mcp_config.py`` deliberately scoped this residual away —
its docstring names "the shape of the attestation payload itself
(``capabilityAttestation`` is not an object, or an object missing a required
field). That is ``Attestation.from_dict``'s concern". This module is that
concern, for all four call sites.
"""

from __future__ import annotations

import inspect
import json

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import Attestation


def _runner():
    """A ``CliRunner`` whose ``stdout`` cannot be polluted by stderr.

    click 8.2 removed ``mix_stderr`` and began separating the streams itself;
    older releases need it passed explicitly. The repo's CI resolves both click
    generations, hence the feature check rather than a pinned assumption.
    """
    if "mix_stderr" in inspect.signature(CliRunner.__init__).parameters:
        return CliRunner(mix_stderr=False)
    return CliRunner()


def _write(tmp_path, name: str, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return path


def _valid_document(**extra) -> dict:
    document = {
        "issuer": "agent://planner",
        "subject": "agent://worker",
        "capability": "CAN_READ(store)",
        "issued_at": "2020-01-01T00:00:00+00:00",
        "ttl_seconds": 300,
    }
    document.update(extra)
    return document


def _without(document: dict, key: str) -> dict:
    return {k: v for k, v in document.items() if k != key}


class TestFromDictRejectsWhatItCannotParse:
    """The choke point every caller routes through."""

    def test_a_non_object_payload_raises_a_value_error(self):
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict([])

        assert "must be a JSON object" in str(caught.value)
        assert "array" in str(caught.value)

    @pytest.mark.parametrize("missing", ["issuer", "subject", "capability", "issued_at"])
    def test_a_missing_required_field_names_it(self, missing):
        with pytest.raises(ValueError) as caught:
            Attestation.from_dict(_without(_valid_document(), missing))

        assert missing in str(caught.value)
        assert "missing required field" in str(caught.value)

    def test_no_input_shape_escapes_as_keyerror_or_typeerror(self):
        """The reported defect, one level down: the parser must be total."""
        for bad in ([], "oops", 3, None, True, {"issuer": "a"}):
            try:
                Attestation.from_dict(bad)
            except ValueError:
                pass
            else:  # pragma: no cover - the assertion below is the point
                raise AssertionError(f"from_dict accepted {bad!r}")

    def test_a_well_formed_document_still_parses(self):
        """Guard the guard: the stricter check must not reject a good document."""
        attestation = Attestation.from_dict(_valid_document())

        assert attestation.issuer == "agent://planner"
        assert attestation.ttl_seconds == 300


class TestValidateReportsMalformedInputAsExitTwo:
    def test_a_non_object_payload_exits_two_without_a_traceback(self, tmp_path):
        path = _write(tmp_path, "arr.json", [])

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 2, result.output
        assert "Traceback" not in result.output
        assert "must be a JSON object" in result.output
        assert "got array" in result.output

    def test_a_missing_required_field_exits_two(self, tmp_path):
        path = _write(tmp_path, "bad.json", _without(_valid_document(), "issued_at"))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 2, result.output
        assert "issued_at" in result.output
        assert "Traceback" not in result.output


class TestCheckChainReportsAMalformedElementAsExitTwo:
    def test_a_missing_field_names_the_failing_index(self, tmp_path):
        chain = [_valid_document(), _without(_valid_document(), "issued_at")]
        path = _write(tmp_path, "chain.json", chain)

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 2, result.output
        assert "chain[1]" in result.output
        assert "issued_at" in result.output
        assert "Traceback" not in result.output

    def test_a_non_object_element_exits_two(self, tmp_path):
        path = _write(tmp_path, "chain.json", [_valid_document(), "oops"])

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 2, result.output
        assert "chain[1]" in result.output
        assert "got string" in result.output

    def test_a_well_formed_chain_is_not_reported_as_malformed(self, tmp_path):
        """An expired hop is invalid (exit 1), never a malformed input (exit 2)."""
        path = _write(tmp_path, "chain.json", [_valid_document()])

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 1, result.output
        assert "chain[" not in result.output


class TestCheckMcpReportsAMalformedAttestationAsExitTwo:
    """The element level, which the config guard above it deliberately left out."""

    def _config(self, attestation) -> dict:
        return {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "capabilityAttestation": attestation,
                }
            }
        }

    def test_a_non_object_capability_attestation_exits_two(self, tmp_path):
        path = _write(tmp_path, "mcp.json", self._config([]))

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 2, result.output
        assert '"filesystem"' in result.output
        assert "capabilityAttestation" in result.output
        assert "Traceback" not in result.output

    def test_a_missing_required_field_exits_two(self, tmp_path):
        path = _write(
            tmp_path, "mcp.json", self._config(_without(_valid_document(), "issued_at"))
        )

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 2, result.output
        assert "issued_at" in result.output

    def test_a_well_formed_attestation_still_scans(self, tmp_path):
        """Guard the guard: one real server must still be scanned, not rejected."""
        document = _valid_document(
            issuer="mcp://filesystem",
            subject="mcp://filesystem/consumer",
            capability="MCP_SERVER_ATTACHED:filesystem",
        )
        path = _write(tmp_path, "mcp.json", self._config(document))

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code != 2, result.output
        assert "MCP_SERVER_ATTACHED:filesystem" in result.output


class TestScanCountsEveryFileItFound:
    """The summary must describe the directory, not the files it could parse."""

    def test_a_malformed_file_is_counted_in_the_summary(self, tmp_path):
        _write(tmp_path, "ok.attestation.json", _valid_document())
        _write(
            tmp_path, "noissued.attestation.json", _without(_valid_document(), "issued_at")
        )

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output
        assert "2 attestations scanned" in result.output
        assert "1 unreadable" in result.output

    def test_the_json_document_also_lists_the_malformed_file(self, tmp_path):
        """A JSON consumer must see the file too, not a quietly smaller list."""
        _write(tmp_path, "ok.attestation.json", _valid_document())
        _write(tmp_path, "arr.attestation.json", [])

        result = _runner().invoke(
            cli, ["scan", str(tmp_path), "--json-output"]
        )

        assert result.exit_code == 1, result.output
        payload = json.loads(result.stdout)
        assert len(payload) == 2
        assert any(entry.get("unreadable") for entry in payload)
        listed = " ".join(str(entry.get("file")) for entry in payload)
        assert "arr.attestation.json" in listed

    def test_a_clean_directory_says_nothing_about_unreadable_files(self, tmp_path):
        _write(tmp_path, "ok.attestation.json", _valid_document())

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert "1 attestations scanned" in result.output
        assert "unreadable" not in result.output
