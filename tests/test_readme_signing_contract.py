"""Issue #41: the README has to state the signing contract, and the recipe it
shows has to be the one the verifier accepts.

The README described *what* is signed ("every field except ``signature``") but
not *how* it is serialized. An issuer written from the README alone therefore
signed ``json.dumps(body)``, and the verifier answered "attestation may be
forged" — the one diagnosis the section gave no way to rule out.

These tests tie the documentation half of the contract to the executable half:

* the Signature Verification section names the exported serialization
  (``canonical_bytes``) and cross-links the ``ed25519:`` prefix, so the section
  cannot silently drift back to describing the fields without the bytes;
* the signing recipe the section shows is extracted from the README and run, so
  a reader who follows it produces a signature this verifier accepts — and a
  signer using the ambient ``json.dumps`` form the section warns against is
  rejected.

The serialization's own properties are pinned behaviourally in
``test_canonical_bytes.py``; this file pins that the README *points at* it.
"""

from __future__ import annotations

import json
import pathlib
import re
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_capability_attestation.models import Attestation, AttestationValidator

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"


def _section() -> str:
    text = README.read_text(encoding="utf-8")
    match = re.search(
        r"^## Signature Verification$(.*?)(?=^## )", text, re.S | re.M
    )
    assert match, "README no longer has a '## Signature Verification' section"
    return match.group(1)


def _documented_recipe() -> str:
    blocks = re.findall(r"```python\n(.*?)```", _section(), re.S)
    assert blocks, "the Signature Verification section shows no python signing recipe"
    return blocks[-1]


def _attestation() -> Attestation:
    return Attestation(
        issuer="agent://planner-v2",
        subject="agent://worker-v3",
        capability="CAN_READ(store:p1)",
        issued_at=datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc),
        ttl_seconds=120,
    )


class TestReadmeStatesTheContract:
    def test_names_the_exported_serialization(self):
        """The section must name the callable an issuer is meant to sign with."""
        assert "canonical_bytes" in _section()

    def test_cross_links_the_algorithm_prefix(self):
        """The serialization and the `ed25519:` prefix belong to one contract."""
        assert "ed25519:" in _section()


class TestTheDocumentedRecipe:
    def test_a_signer_following_the_readme_is_accepted(self):
        """Run the section's own snippet: it must produce a verified signature."""
        key = ed25519.Ed25519PrivateKey.generate()
        att = _attestation()
        scope: dict = {"attestation": att, "private_key": key}
        exec(_documented_recipe(), scope)  # the README snippet is the subject here
        att.signature = scope["signature"]

        assert AttestationValidator().verify_signature(att, key.public_key()) is True

    def test_the_recipe_the_section_warns_against_is_rejected(self):
        """The ambient `json.dumps` form the section names must not verify.

        This is the failure the section exists to warn about; it keeps the
        warning honest rather than decorative.
        """
        key = ed25519.Ed25519PrivateKey.generate()
        att = _attestation()
        body = {k: v for k, v in att.to_dict().items() if k != "signature"}
        att.signature = key.sign(json.dumps(body).encode()).hex()

        assert AttestationValidator().verify_signature(att, key.public_key()) is False
