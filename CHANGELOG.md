# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `AttestationValidator(trusted_keys=..., require_signature=...)`: signature
  verification is now part of validation, and the verdict is reported as
  `ValidationResult.signature_status` (`verified` / `unverified` / `unsigned` /
  `unchecked`).
- `--public-key-file` and `--require-signature` on `aca validate`, `aca scan`,
  `aca check-chain` and `aca check-mcp`.
- `DelegationChain.validate_monotonicity(validator=...)` applies the
  signature check to every hop when a validator is given.

### Changed

- The CLI always prints the signature verdict alongside `VALID`/`STALE`, so an
  unverified attestation is never reported as a bare `✓ VALID`.
- `--json-output` includes `signature_status`.
- A non-stale invalid attestation now prints `✗ INVALID` instead of `✗ STALE`.

### Fixed

- `verify_signature()` was never called by `validate()` or any CLI command, so a
  tampered attestation (`db:read` → `db:admin`, swapped tool schema, stretched
  TTL) was reported `VALID` with exit code 0 (fixes #15).
- `verify_signature()` returned an uncaught `TypeError` for a non-string
  signature instead of `False`.

## [Initial Release]

- Initial project release
