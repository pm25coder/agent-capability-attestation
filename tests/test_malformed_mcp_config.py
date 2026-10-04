"""Tests that a structurally malformed MCP config reports exit 2, not a traceback.

``check_mcp`` walks a config as *document → server collection → server entry*
and reads each level as a JSON object. When one of those levels was a JSON
array, string, number or null the walk raised an uncaught ``AttributeError``
and the process exited ``1`` — the very code a genuine validation failure uses,
so ``aca check-mcp`` could not tell an operator with a broken config file apart
from one whose attestations were stale. The CLI already maps its other
malformed-input paths (missing file, invalid JSON, non-array ``check-chain``
input) to exit 2; these tests pin the same verdict for a malformed config.

The residual that is deliberately *not* covered here is the shape of the
attestation payload itself (``capabilityAttestation`` is not an object, or an
object missing a required field). That is ``Attestation.from_dict``'s concern
and the same hole ``check-chain`` reaches through a malformed chain element;
this module holds the boundary to the config's container levels.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.mcp_scanner import McpConfigError, check_mcp


def _write_mcp_config(tmp_path, document):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(document))
    return path


def _invoke(tmp_path, document):
    return CliRunner().invoke(cli, ["check-mcp", str(_write_mcp_config(tmp_path, document))])


def _valid_server():
    return {
        "command": "npx",
        "capabilityAttestation": {
            "issuer": "mcp://filesystem",
            "subject": "mcp://filesystem/consumer",
            "capability": "MCP_SERVER_ATTACHED:filesystem",
            # Fresh, and not future-dated: a future issued_at is itself rejected.
            "issued_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            "ttl_seconds": 300,
        },
    }


class TestDocumentIsNotAnObject:
    """The whole config file must be a JSON object."""

    def test_json_array_document_exits_two(self, tmp_path):
        result = _invoke(tmp_path, [])

        assert result.exit_code == 2, result.output
        assert "must be a JSON object" in result.output

    def test_json_string_document_exits_two(self, tmp_path):
        result = _invoke(tmp_path, "oops")

        assert result.exit_code == 2, result.output
        assert "got string" in result.output

    def test_no_traceback_in_output(self, tmp_path):
        """The regression was a traceback; assert its absence, not just the code."""
        result = _invoke(tmp_path, [])

        assert "Traceback" not in result.output
        assert "AttributeError" not in result.output


class TestServerCollectionIsNotAnObject:
    """``mcpServers`` (or its ``servers`` alias) must be a JSON object."""

    def test_mcp_servers_array_exits_two(self, tmp_path):
        result = _invoke(tmp_path, {"mcpServers": []})

        assert result.exit_code == 2, result.output
        assert '"mcpServers"' in result.output
        assert "got array" in result.output

    def test_mcp_servers_string_exits_two(self, tmp_path):
        result = _invoke(tmp_path, {"mcpServers": "oops"})

        assert result.exit_code == 2, result.output
        assert "got string" in result.output

    def test_mcp_servers_null_exits_two(self, tmp_path):
        result = _invoke(tmp_path, {"mcpServers": None})

        assert result.exit_code == 2, result.output
        assert "got null" in result.output

    def test_mcp_servers_number_exits_two(self, tmp_path):
        result = _invoke(tmp_path, {"mcpServers": 3})

        assert result.exit_code == 2, result.output
        assert "got number" in result.output

    def test_servers_alias_array_is_named_by_its_own_key(self, tmp_path):
        """The message must name the key that actually supplied the value."""
        result = _invoke(tmp_path, {"servers": []})

        assert result.exit_code == 2, result.output
        assert '"servers"' in result.output
        assert '"mcpServers"' not in result.output


class TestServerEntryIsNotAnObject:
    """Each server in the collection must itself be a JSON object."""

    def test_server_entry_string_exits_two(self, tmp_path):
        result = _invoke(tmp_path, {"mcpServers": {"filesystem": "oops"}})

        assert result.exit_code == 2, result.output
        assert '"filesystem"' in result.output
        assert "got string" in result.output

    def test_server_entry_array_exits_two(self, tmp_path):
        result = _invoke(tmp_path, {"mcpServers": {"filesystem": []}})

        assert result.exit_code == 2, result.output
        assert '"filesystem"' in result.output
        assert "got array" in result.output


class TestScannerRaisesTheTypedError:
    """The scanner is a public helper; pin the error it raises on a bad config."""

    def test_check_mcp_raises_mcp_config_error(self, tmp_path):
        path = _write_mcp_config(tmp_path, {"mcpServers": []})

        try:
            check_mcp(str(path))
        except McpConfigError:
            pass
        else:  # pragma: no cover - the assertion below is the point
            raise AssertionError("check_mcp accepted a malformed config")

    def test_mcp_config_error_is_a_value_error(self):
        """So a caller that already catches ValueError keeps working."""
        assert issubclass(McpConfigError, ValueError)


class TestGuardTheGuard:
    """The stricter validation must not reject a well-formed config."""

    def test_populated_config_still_scans(self, tmp_path):
        result = _invoke(tmp_path, {"mcpServers": {"filesystem": _valid_server()}})

        assert result.exit_code == 0, result.output
        assert "MCP_SERVER_ATTACHED:filesystem" in result.output

    def test_config_without_servers_still_reports_emptiness(self, tmp_path):
        """An object with no servers is empty, not malformed: exit 1, not 2."""
        result = _invoke(tmp_path, {})

        assert result.exit_code == 1, result.output
        assert "no servers" in result.output

    def test_empty_server_map_still_reports_emptiness(self, tmp_path):
        result = _invoke(tmp_path, {"mcpServers": {}})

        assert result.exit_code == 1, result.output
        assert "no servers" in result.output
