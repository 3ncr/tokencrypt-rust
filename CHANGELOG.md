# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-04-22

Initial release. Stable Rust API for the
[3ncr.org v1](https://3ncr.org/1/) encryption envelope (AES-256-GCM,
12-byte random IV, 16-byte GCM tag). MSRV 1.85.

### Added

- `TokenCrypt::from_raw_key(key)` — primary constructor for callers with a
  32-byte AES-256 key.
- `TokenCrypt::from_sha3(secret)` — single SHA3-256 hash for high-entropy
  secrets that are not already 32 bytes (random API tokens, UUIDs, etc.).
- `TokenCrypt::from_argon2id(secret, salt)` — Argon2id KDF for
  password-strength secrets. Parameters match the
  [3ncr.org v1 spec](https://3ncr.org/1/#kdf):
  `m=19456 KiB, t=2, p=1`, 32-byte output, salt ≥ 16 bytes.
- `encrypt_3ncr(plaintext)` / `decrypt_if_3ncr(value)` — encrypt to the
  `3ncr.org/1#…` envelope and decrypt only values that carry the header,
  passing everything else through unchanged (`Cow::Borrowed` on the
  passthrough path, `Cow::Owned` after decryption).
- `TokenCryptError` — single error type for decryption failures
  (bad tag, truncated input, malformed base64).

### Notes

- Cross-verified against the canonical v1 test vectors shared with the Go,
  Node.js, PHP, and Python reference implementations.
- Per 3ncr.org's new-language convention, the legacy PBKDF2-SHA3 KDF is
  intentionally omitted — there is no pre-existing Rust data to decrypt.
  Callers needing it can derive the key with a PBKDF2-SHA3-256 implementation
  (e.g. the `pbkdf2` crate with `Sha3_256`) and pass the result to
  `from_raw_key`.

[1.0.0]: https://github.com/3ncr/tokencrypt-rust/releases/tag/v1.0.0
