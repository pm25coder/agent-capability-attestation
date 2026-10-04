# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- A `lint` job in CI running `ruff check .` (package **and** `tests/`), with the
  rule set pinned in a new `ruff.toml` at the repo root.

- `AttestationValidator(max_skew_seconds=...)` and a `--max-skew-seconds` option on
  `validate`, `scan`, `check-chain` and `check-mcp` to bound how far into the future an
  `issued_at` may sit. Defaults to `DEFAULT_MAX_SKEW_SECONDS` (60s).
- `AttestationValidator(trusted_keys=..., require_signature=...)`: signature
  verification is now part of validation, and the verdict is reported as
  `ValidationResult.signature_status` (`verified` / `unverified` / `unsigned` /
  `unchecked`).
- `--public-key-file` and `--require-signature` on `aca validate`, `aca scan`,
  `aca check-chain` and `aca check-mcp`.
- `DelegationChain.validate_monotonicity(validator=...)` runs the validator over
  every hop when one is given — not just its signature check, but the full
  per-attestation validation.

### Changed

- The CLI always prints the signature verdict alongside `VALID`/`STALE`, so an
  unverified attestation is never reported as a bare `✓ VALID`.
- `--json-output` includes `signature_status`.
- A non-stale invalid attestation now prints `✗ INVALID` instead of `✗ STALE`.

### Fixed

- A declared `expires_at` can no longer extend an attestation's life past
  `issued_at + ttl_seconds`. The field is attacker-controlled — it is one of the
  values an editor of the file chooses — and it was used as *the* deadline, so an
  attestation issued 30 days ago with `ttl_seconds: 1` and `expires_at: 2099`
  reported `✓ VALID`, `is_valid` was `True`, `errors` was empty and `aca validate`
  exited `0`; the only trace was a warning saying the tool was deliberately
  honouring the declared value. No value of `--max-ttl` closed it, because
  `max_ttl` is compared against `ttl_seconds`, which no longer decided expiry once
  the field was present. A declared expiry later than the TTL-derived deadline is
  now an error, and the staleness reading is recomputed against that deadline, so
  the verdict is `STALE` rather than merely `INVALID`. The opposite direction is
  unchanged: an attestation that declares itself expired is still honoured even
  when its TTL has not run out (#11), and a live chain hop with a declared expiry
  in the past is still rejected (#22). `max_ttl` itself remains advisory — that is
  #18, and the bound here is the TTL-derived deadline rather than the policy
  ceiling so that #18's contract is not changed by this fix.

- `aca scan` now exits `1` when any attestation it scanned is invalid, instead
  of exiting `0` unless `--fail-on-stale` was passed. The verdict lines were
  already correct — a forged signature reported `ERROR: Signature does not match
  payload — attestation may be forged` — but `all_valid` was computed and then
  discarded at the process boundary, so a CI gate that ran `aca scan ./agents/`
  and checked the exit status passed a directory full of forged and expired
  attestations. That made `scan` the only validating command whose exit code
  disagreed with its own findings (`validate`, `check-chain` and `check-mcp` all
  fail closed). The default is now fail-closed; `--report-only` is the explicit
  opt-out, and `--fail-on-stale` is kept as a deprecated, redundant alias for one
  release so the documented CI recipe keeps working. The two flags are
  mutually exclusive (exit `2`).

- `check-mcp` now reports exit `2` for a config whose structure is not the nested
  JSON object the scanner reads, instead of dying with an uncaught
  `AttributeError` and exiting `1`. A `"mcpServers"` (or `"servers"`) value that is
  an array, string, number or null — and a server entry that is not an object —
  escaped from the walk as a traceback, and the process then exited `1`, the same
  code a genuine validation failure uses: an operator with a malformed config
  could not tell it apart from one whose attestations were stale. The scanner
  raises `McpConfigError` for each of those levels, naming the key and the JSON
  type it found, and the CLI maps it to exit `2` like its other malformed-input
  paths. The attestation payload's own shape (`capabilityAttestation` not an
  object, or missing a required field) is a separate site with the same root
  cause, reached through `check-chain` as well, and is not covered here.

- `check-chain` never checked TTL, expiry or clock skew: it built an
  `AttestationValidator` from the operator's `--max-ttl` / `--max-skew-seconds`
  and applied only its signature check to each hop, so those options had no
  effect at all on this command. `validate_monotonicity()` compared each hop's
  capability against its parent's and nothing else, which made a chain
  "monotonic" regardless of age. `check-chain` therefore exited `0` and printed
  `✓ VALID` for a chain whose every hop had expired, for one dated 80 years in
  the future, and for one carrying no TTL — the same defect class as #22, #23
  and #24, which hardened `AttestationValidator.validate()` on the
  single-attestation path and left the chain path unhardened. Each hop is now
  validated in full and its verdict merged with the monotonicity one, so one
  `ValidationResult` per hop carries both.

- `verify_signature()` was never called by `validate()` or any CLI command, so a
  tampered attestation (`db:read` → `db:admin`, swapped tool schema, stretched
  TTL) was reported `VALID` with exit code 0 (fixes #15).
- `verify_signature()` returned an uncaught `TypeError` for a non-string
  signature instead of `False`.

- An empty result set is now a failure instead of a vacuous pass. `check-chain`
  and `check-mcp` both reduce their verdict with `all(...)`, and `all([])` is
  `True`, so `check-chain []` and `check-mcp {}` exited `0` having printed
  nothing at all. A run that inspected nothing was indistinguishable from a
  clean one. Both now report the empty set on stderr and exit `1`.

- A future-dated `issued_at` is now rejected instead of validating forever. `validate()`
  computed a negative `age` for a timestamp ahead of the clock and had no branch for it,
  so an attestation dated 80 years in the future reported `is_valid=True`, `is_stale=False`
  and CLI exit `0` — and, because the deadline is derived from `issued_at`, could not expire
  until the wall clock caught up. Rejected beyond the skew window with
  `Attestation issued <n>s in the future (allowed skew 60s)`.
- `verify_signature()` no longer raises `TypeError` for a `signature` value that is not a
  string. `bytes.fromhex()` raises `TypeError` — not `ValueError` — for a JSON number,
  array or object, so the previous `except (InvalidSignature, ValueError)` let
  attacker-controlled input escape as an uncaught exception instead of returning `False`.
  It also accepts the algorithm-prefixed `"ed25519:<hex>"` form documented by the README's
  Attestation Schema, which `bytes.fromhex` rejected with `ValueError` — so every
  signature written in the project's own documented wire format failed verification.

## [Initial Release]

- Initial project release
