# Agent Capability Attestation

> Detect capability drift and stale attestations in AI agent delegation chains. TTL-based freshness validation for agent-to-agent capability negotiation.

## The Problem

When Agent A delegates a task to Agent B, the capability attestation that authorized the delegation has a half-life. After deployment, context changes, or capability revocation, the cached attestation becomes a liability — Agent B may still hold permissions it shouldn't, or Agent A may operate under the false belief that the chain is still valid.

**Real-world impact:**
- 18% of "phantom capabilities" appear in the first 2 seconds after a deployment rollout (cached receipt looks fresh, backend is dead)
- 13% of agent handshakes in production meshes have silent capability mismatches
- Multi-hop delegation chains compound the staleness: A→B→C→D, if any link is stale, the entire downstream delegation operates on fiction

**Current gap:** No open-source tool validates capability attestation TTLs or detects drift in delegation chains.

## What This Tool Does

`agent-capability-attestation` validates that agent capability attestations:

1. **Carry TTL metadata** — every attestation must include `{capability, agent_state_hash, timestamp, ttl}`
2. **Are fresh** — TTL must not have expired at validation time
3. **Match the current agent state** — the state hash must match the agent's current declared capabilities
4. **Delegate monotonically** — each hop in a delegation chain must narrow (never expand) the scope
5. **Fail closed** — missing TTL = expired attestation (assume stale unless freshly attested)

## Installation

```bash
pip install git+https://github.com/yunaremaia/agent-capability-attestation.git
```

## Quick Start

```bash
# Validate a single attestation file
aca validate attestation.json

# Scan a delegation chain directory
aca scan ./delegation-chain/

# Check MCP server capability attestations
aca check-mcp mcp-config.json --max-ttl 300

# Exit code: 0 = all fresh, 1 = stale/drift detected
echo $?
```

## Signature Verification

An attestation's `signature` is an Ed25519 signature over the whole payload
(every field except `signature` itself). **Validation enforces it.** Swapping
the capability, subject, TTL or tool schema after signing makes validation
fail:

```console
$ aca validate attestation.json --public-key-file issuer-pubkey.hex
✗ INVALID | agent://planner-v2 → agent://worker-v3 | CAN_DELETE_ALL(state_store) (TTL 120s)
    signature: NOT VERIFIED
    ERROR: Signature does not match payload — attestation may be forged
$ echo $?
1
```

`--public-key-file` takes the issuer's Ed25519 public key as 64 hex
characters:

```bash
# Publish the key (issuer side)
python -c "from agent_capability_attestation.models import Attestation; \
print(priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, \
format=serialization.PublicFormat.Raw).hex())" > issuer-pubkey.hex

# Consume it (verifier side)
aca validate attestation.json --public-key-file issuer-pubkey.hex
```

Both options are accepted by `validate`, `scan`, `check-chain` and
`check-mcp`.

### What happens without a key

| attestation | default | `--require-signature` |
|---|---|---|
| correctly signed | `signature: VERIFIED`, exit 0 | `VERIFIED`, exit 0 |
| signed but tampered with | `NOT VERIFIED`, **exit 1** | exit 1 |
| signed, no trusted key for the issuer | `NOT VERIFIED`, **exit 1** | exit 1 |
| no signature at all | `UNSIGNED — NOT VERIFIED`, warning, exit 0 | **exit 1** |

The rule is: **a signature that cannot be verified is treated as no evidence
at all and rejected** — accepting it would reintroduce the exact hole the
signature exists to close. An attestation with *no* signature is a different
case: it never claimed to be signed, and the unsigned workflow documented
above keeps working. It is still reported as unverified, and
`--require-signature` turns it into a hard failure for deployments that demand
every attestation be signed.

Use `--require-signature` in any gate that trusts the payload:

```yaml
- name: Validate agent capability attestations
  run: |
    pip install git+https://github.com/yunaremaia/agent-capability-attestation.git
    aca scan ./agents/ --fail-on-stale --require-signature \
      --public-key-file ./keys/issuer-pubkey.hex
```

## Attestation Schema

```json
{
  "issuer": "agent://planner-v2",
  "subject": "agent://worker-v3",
  "capability": "CAN_WRITE(state_store:partition_3)",
  "issued_at": "2026-09-21T12:00:00Z",
  "expires_at": "2026-09-21T12:02:00Z",
  "ttl_seconds": 120,
  "state_hash": "sha256:abc123...",
  "provenance": ["agent://planner-v2", "agent://coordinator-v1"],
  "signature": "ed25519:def456..."
}
```

## Integration

### CI/CD Gate

```yaml
- name: Validate agent capability attestations
  run: |
    pip install git+https://github.com/yunaremaia/agent-capability-attestation.git
    aca scan ./agents/ --fail-on-stale --require-signature \
      --public-key-file ./keys/issuer-pubkey.hex
```

### Pre-delegation Check

`AttestationValidator` takes the trusted public keys so the signature is
verified as part of validation:

```python
from agent_capability_attestation import AttestationValidator

validator = AttestationValidator(
    max_ttl=300,
    trusted_keys={"agent://planner-v2": planner_public_key},
)
result = validator.validate(attestation)

if result.is_stale:
    raise CapabilityExpiredError(
        f"Attestation expired {result.stale_by_seconds}s ago"
    )

# A signed payload that could not be verified is already invalid; an
# attestation that never claimed a signature is reported as such.
if result.signature_status != "verified":
    raise CapabilityNotAttested(result.signature_status)
```

## Roadmap

- [ ] A2A protocol integration (validate Agent Card capability declarations)
- [ ] MCP server capability scanning
- [ ] Delegation chain visualization
- [ ] SARIF output for GitHub Code Scanning
- [ ] Policy engine integration (OPA/Rego)
- [ ] Prometheus metrics exporter

## License

MIT

# Agent Capability Attestation

![CI](https://github.com/yunaremaia/agent-capability-attestation/actions/workflows/ci.yml/badge.svg)
