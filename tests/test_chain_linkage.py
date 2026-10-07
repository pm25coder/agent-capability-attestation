"""Tests that ``check-chain`` rejects hops that do not link, and anchors scope prefixes.

``DelegationChain.validate_monotonicity()`` compared each hop's capability against
its parent's and nothing else. So a file holding two *unrelated* delegations —
hop 0 issued to ``agent://worker``, hop 1 issued by ``agent://attacker`` —
reported ``✓ VALID`` at every hop and ``check-chain`` exited ``0``: a
"delegation chain" whose hops do not delegate to one another was indistinguishable
from a real one.

The same helper, ``_scope_is_subscope``, treated any raw string prefix as a
narrowing. ``db:readwrite`` textually extends ``db:read`` and ``storefront:delete``
extends ``store``, so both were classified as the *narrower* scope — a privilege
**expansion** reported as monotonic, and ``CAN_WRITE`` covered
``CAN_WRITE_ANYTHING``. An empty parent matched everything (that half was already
closed); the unanchored non-empty prefix was not.

Both fixes are the same rule on the same check: what it is handed must be
*related* to what it is compared against — linked by subject, or separated by a
real namespace boundary — rather than merely sharing a textual prefix.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import (
    Attestation,
    DelegationChain,
    _scope_is_subscope,
)

#: A narrowing parent scope, so monotonicity passes for the chains built here.
PARENT_SCOPE = "CAN_WRITE(store:*)"
#: A strict sub-scope of ``PARENT_SCOPE``.
CHILD_SCOPE = "CAN_WRITE(store:partition_1)"


def _issued(offset_seconds: float = 5) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()


def _hop(issuer: str, subject: str, capability: str, issued_at: str | None = None) -> dict:
    """One live hop, issued by ``issuer`` to ``subject``."""
    return {
        "issuer": issuer,
        "subject": subject,
        "capability": capability,
        "issued_at": issued_at or _issued(),
        "ttl_seconds": 120,
    }


def _write(tmp_path, chain, name="chain.json"):
    path = tmp_path / name
    path.write_text(json.dumps(chain))
    return path


def _run(path):
    return CliRunner().invoke(cli, ["check-chain", str(path)])


class TestHopsMustLinkToTheirParent:
    """The first defect: an unlinked pair of delegations passed as a chain."""

    def test_the_reported_disjoint_pair_exits_one(self, tmp_path):
        """The issue's exact fixture: two unrelated delegations, concatenated."""
        path = _write(
            tmp_path,
            [
                _hop("agent://planner", "agent://worker", "store:read"),
                _hop("agent://attacker", "agent://mallory", "store:read"),
            ],
        )

        result = _run(path)

        assert result.exit_code == 1, result.output
        assert "is not the previous hop's subject" in result.output

    def test_a_linked_pair_is_the_control(self, tmp_path):
        """Only the linkage differs from the failing chain above."""
        path = _write(
            tmp_path,
            [
                _hop("agent://planner", "agent://worker", "store:read"),
                _hop("agent://worker", "agent://worker2", "store:read"),
            ],
        )

        result = _run(path)

        assert result.exit_code == 0, result.output

    def test_the_error_names_both_sides_of_the_break(self, tmp_path):
        """The *error line* names both ends, not just the hop header above it.

        The ``[Hop i]`` header prints the issuer and subject anyway, so an
        assertion over the whole output would pass even if the error message
        named neither — this reads the ``ERROR:`` line specifically.
        """
        path = _write(
            tmp_path,
            [
                _hop("agent://planner", "agent://worker", CHILD_SCOPE),
                _hop("agent://attacker", "agent://mallory", CHILD_SCOPE),
            ],
        )

        output = _run(path).output
        error = next(
            line for line in output.splitlines() if line.strip().startswith("ERROR:")
        )

        assert "agent://attacker" in error
        assert "agent://worker" in error

    def test_every_hop_is_checked_against_its_own_parent(self, tmp_path):
        """A three-hop chain with one break in the middle fails only at hop 2."""
        path = _write(
            tmp_path,
            [
                _hop("a", "b", PARENT_SCOPE),
                _hop("b", "c", CHILD_SCOPE),
                _hop("c", "d", CHILD_SCOPE),
                _hop("WRONG", "e", CHILD_SCOPE),
            ],
        )

        results = DelegationChain(
            attestations=[Attestation.from_dict(h) for h in json.loads(path.read_text())]
        ).validate_monotonicity()

        assert results[0].is_valid
        assert results[1].is_valid
        assert results[2].is_valid
        assert not results[3].is_valid
        assert "not the previous hop's subject" in results[3].errors[0]

    def test_a_single_hop_has_no_parent_to_link_to(self, tmp_path):
        """The check applies between hops, so a lone hop is unaffected."""
        path = _write(tmp_path, [_hop("a", "b", PARENT_SCOPE)])

        assert _run(path).exit_code == 0

    def test_a_linked_chain_still_narrows(self, tmp_path):
        """The linkage check must not disturb the scope verdict it sits beside."""
        path = _write(
            tmp_path,
            [
                _hop("a", "b", CHILD_SCOPE),
                _hop("b", "c", PARENT_SCOPE),
            ],
        )

        result = _run(path)

        assert result.exit_code == 1
        assert "capability expanded" in result.output
        assert "is not the previous hop's subject" not in result.output


#: A textual extension of the parent that is not in its namespace.
EXPANSIONS = [
    # The issue's headline: a write scope read out of a read scope.
    ("db:read", "db:readwrite"),
    ("store", "storefront:delete"),
    ("CAN_WRITE", "CAN_WRITE_ANYTHING"),
    ("fs:read", "fs:read_secret_keys"),
    ("agent:tool", "agent:toolbelt:wipe"),
    ("read", "readwrite"),
]

#: The boundary that must still count as a namespace, not a prefix accident.
BOUNDARIES = [
    ("db", "db:read"),
    ("fs", "fs/read"),
    ("db:*", "db:read"),
    ("CAN_WRITE(store:*)", "CAN_WRITE(store:partition_1)"),
    ("store:read", "store:read"),
]


@pytest.mark.parametrize("parent,child", EXPANSIONS)
def test_a_textual_extension_is_not_a_subscope(parent, child):
    assert not _scope_is_subscope(parent, child)


@pytest.mark.parametrize("parent,child", BOUNDARIES)
def test_a_real_namespace_boundary_is_a_subscope(parent, child):
    assert _scope_is_subscope(parent, child)


def test_the_reported_scope_expansion_is_rejected_end_to_end(tmp_path):
    """The issue's second fixture through the CLI, not just the helper."""
    path = _write(
        tmp_path,
        [
            _hop("agent://a", "agent://b", "db:read"),
            _hop("agent://b", "agent://c", "db:readwrite"),
        ],
    )

    result = _run(path)

    assert result.exit_code == 1, result.output
    assert "capability expanded" in result.output


def test_a_narrowed_pair_still_exits_zero(tmp_path):
    """Positive control: widening the boundary check must not reject a narrowing."""
    path = _write(
        tmp_path,
        [
            _hop("agent://a", "agent://b", "CAN_WRITE(store:*)"),
            _hop("agent://b", "agent://c", "CAN_WRITE(store:p1)"),
        ],
    )

    assert _run(path).exit_code == 0
