"""Tool to scan MCP server configurations for capability drift."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    DEFAULT_MAX_SKEW_SECONDS,
    Attestation,
    AttestationValidator,
    ValidationResult,
)


class McpConfigError(ValueError):
    """An MCP config is not the nested JSON object the scanner reads.

    ``check_mcp`` walks a config as *document → server collection → server
    entry*. When one of those levels is a JSON array, string, number or null
    the walk escaped as an uncaught ``AttributeError``, which exits 1 — the
    same code a genuine validation failure uses, so a malformed config was
    indistinguishable from a stale one. The CLI maps this error to exit 2,
    which is what its other malformed-input paths already report.
    """


def _json_type(value: Any) -> str:
    """Name a value's JSON type the way the messages above read it."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


def check_mcp(
    config_path: str,
    max_ttl: int = 300,
    now: Any = None,
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
    trusted_keys: Any = None,
    require_signature: bool = False,
) -> list["ValidationResult"]:
    """Scan an MCP server configuration for capability attestations.

    Detects when MCP server tool schemas have drifted from their attestations.

    ``trusted_keys`` and ``require_signature`` are forwarded to the validator
    so a signature check configured by the caller applies to every attestation
    embedded in the config — without them an MCP attestation could be rewritten
    to claim a wider tool schema and would still be reported VALID.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"MCP config not found: {config_path}")

    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise McpConfigError(
            f"MCP config must be a JSON object, got {_json_type(data)}"
        )
    results = []
    validator = AttestationValidator(
        max_ttl=max_ttl,
        now=now,
        max_skew_seconds=max_skew_seconds,
        trusted_keys=trusted_keys,
        require_signature=require_signature,
    )

    # MCP configs can list servers under a "mcpServers" or similar key
    servers = data.get("mcpServers", data.get("servers", {}))
    servers_key = "mcpServers" if "mcpServers" in data else "servers"
    if not isinstance(servers, dict):
        raise McpConfigError(
            f'MCP config "{servers_key}" must be a JSON object, '
            f"got {_json_type(servers)}"
        )

    for server_name, server_config in servers.items():
        if not isinstance(server_config, dict):
            raise McpConfigError(
                f'MCP server "{server_name}" must be a JSON object, '
                f"got {_json_type(server_config)}"
            )
        att_data = server_config.get("capabilityAttestation")
        if att_data is None:
            # No attestation present — create a synthetic one to flag
            att = Attestation(
                issuer=f"mcp://{server_name}",
                subject=f"mcp://{server_name}/consumer",
                capability=f"MCP_SERVER_ATTACHED:{server_name}",
                issued_at=__import__("datetime").datetime(
                    2020, 1, 1, tzinfo=__import__("datetime").timezone.utc
                ),
                ttl_seconds=0,
                state_hash=None,
            )
            result = validator.validate(att)
            results.append(result)
            continue

        att = Attestation.from_dict(att_data)
        result = validator.validate(att)
        results.append(result)

    return results
