"""Regression tests for issue #19: one canonical serialization for signing and hashing.

Before the fix, two serializations lived in the same module:

* ``compute_state_hash`` used ``json.dumps(capabilities, sort_keys=True)``;
* ``verify_signature`` used ``json.dumps(body)`` — no ``sort_keys``.

Both left ``separators`` and ``ensure_ascii`` at their defaults, so the bytes
hashed were not the compact, key-sorted, UTF-8 form a signer written in another
language reproduces. A correct canonical signer was rejected, and a non-ASCII
payload hashed differently depending on the caller's encoder settings.

These tests pin the single contract, :func:`canonical_bytes`, together with the
control arms that keep it honest: a signer using the old ambient-``json.dumps``
form must now be rejected, so reverting either consumer to its pre-fix call
fails here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_capability_attestation import canonical_bytes, compute_state_hash
from agent_capability_attestation.models import Attestation, AttestationValidator


def _attestation(**overrides) -> Attestation:
    fields = {
        "issuer": "agent://planner-v2",
        "subject": "agent://worker-v3",
        "capability": "CAN_READ(store:p1)",
        "issued_at": datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc),
        "ttl_seconds": 120,
    }
    fields.update(overrides)
    return Attestation(**fields)


def _body(attestation: Attestation) -> dict:
    return {k: v for k, v in attestation.to_dict().items() if k != "signature"}


class TestCanonicalBytesContract:
    def test_exported_from_the_package(self):
        assert callable(canonical_bytes)

    def test_sorted_compact_utf8(self):
        assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
        assert canonical_bytes({"cap": "a\u00e7\u00e3o"}) == (
            '{"cap":"a\u00e7\u00e3o"}'.encode("utf-8")
        )

    def test_key_insertion_order_does_not_change_the_bytes(self):
        first = {"b": 1, "a": {"y": 2, "x": 3}}
        second = {"a": {"x": 3, "y": 2}, "b": 1}
        assert canonical_bytes(first) == canonical_bytes(second)

    def test_no_insignificant_whitespace(self):
        assert canonical_bytes({"a": [1, 2]}) == b'{"a":[1,2]}'

    def test_nan_is_rejected_rather_than_serialized(self):
        with pytest.raises(ValueError):
            canonical_bytes({"a": float("nan")})


class TestStateHashFollowsTheContract:
    def test_hash_is_sha256_of_canonical_bytes(self):
        caps = {"tools": ["search", "write"], "max_tokens": 1000}
        expected = "sha256:" + hashlib.sha256(canonical_bytes(caps)).hexdigest()
        assert compute_state_hash(caps) == expected

    def test_non_ascii_hash_matches_the_compact_utf8_form(self):
        """Defect C: ambient ``ensure_ascii`` must not change the digest."""
        caps = {"cap": "a\u00e7\u00e3o"}
        expected = "sha256:" + hashlib.sha256(
            json.dumps(
                caps, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        assert compute_state_hash(caps) == expected

    def test_key_order_does_not_change_the_digest(self):
        assert compute_state_hash({"a": 1, "b": 2}) == compute_state_hash(
            {"b": 2, "a": 1}
        )


class TestSignatureFollowsTheContract:
    def test_canonical_compact_signer_verifies(self):
        """Defect A: a compact, key-sorted, UTF-8 signer must verify."""
        key = ed25519.Ed25519PrivateKey.generate()
        att = _attestation()
        canonical = json.dumps(
            _body(att), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        att.signature = key.sign(canonical).hex()

        assert AttestationValidator().verify_signature(att, key.public_key()) is True

    def test_the_two_consumers_hash_the_same_bytes(self):
        """The hash path and the signature path are now one function.

        The second assertion is the historical disagreement itself: the old
        signature path's bytes were not the canonical ones.
        """
        key = ed25519.Ed25519PrivateKey.generate()
        att = _attestation()
        att.signature = key.sign(canonical_bytes(_body(att))).hex()

        assert AttestationValidator().verify_signature(att, key.public_key()) is True
        assert canonical_bytes(_body(att)) != json.dumps(_body(att)).encode()

    def test_legacy_default_json_signing_is_rejected(self):
        """Control arm: the old ambient-``json.dumps`` form must no longer verify.

        This is what fails if the verifier is reverted to ``json.dumps(body)``.
        """
        key = ed25519.Ed25519PrivateKey.generate()
        att = _attestation()
        att.signature = key.sign(json.dumps(_body(att)).encode()).hex()

        assert AttestationValidator().verify_signature(att, key.public_key()) is False

    def test_sorted_but_spaced_signing_is_rejected(self):
        """Control arm on the separators axis: ``sort_keys`` alone is not it.

        Fails if the verifier is reverted to ``json.dumps(body, sort_keys=True)``
        — the old ``compute_state_hash`` form.
        """
        key = ed25519.Ed25519PrivateKey.generate()
        att = _attestation()
        att.signature = key.sign(json.dumps(_body(att), sort_keys=True).encode()).hex()

        assert AttestationValidator().verify_signature(att, key.public_key()) is False

    def test_ascii_escaped_non_ascii_signing_is_rejected(self):
        """Control arm on the encoding axis: ``ensure_ascii=True`` is not it."""
        key = ed25519.Ed25519PrivateKey.generate()
        att = _attestation(capability="CAN_READ(store:a\u00e7\u00e3o)")
        escaped = json.dumps(
            _body(att), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        att.signature = key.sign(escaped).hex()

        assert AttestationValidator().verify_signature(att, key.public_key()) is False
