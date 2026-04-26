# threencr (3ncr.org)

[![Test](https://github.com/3ncr/tokencrypt-rust/actions/workflows/test.yml/badge.svg)](https://github.com/3ncr/tokencrypt-rust/actions/workflows/test.yml)
[![Crates.io](https://img.shields.io/crates/v/threencr.svg)](https://crates.io/crates/threencr)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/3ncr/tokencrypt-rust/badge)](https://scorecard.dev/viewer/?uri=github.com/3ncr/tokencrypt-rust)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[3ncr.org](https://3ncr.org/) is a standard for string encryption / decryption
(algorithms + storage format), originally intended for encrypting tokens in
configuration files but usable for any UTF-8 string. v1 uses AES-256-GCM for
authenticated encryption with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

This is the official Rust implementation. See
[github.com/3ncr](https://github.com/3ncr) for implementations in other
languages (Go, Node.js, PHP, Python, Java, C#, Ruby).

## Install

```toml
[dependencies]
threencr = "1"
```

Requires Rust 1.85+.

## Usage

Pick a constructor based on the entropy of your secret — see the
[3ncr.org v1 KDF guidance](https://3ncr.org/1/#kdf) for the canonical
recommendation.

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key, skip the KDF and pass it directly.

```rust
use threencr::TokenCrypt;

let mut key = [0u8; 32];
getrandom::fill(&mut key).expect("system RNG");
let tc = TokenCrypt::from_raw_key(key);
```

For a high-entropy secret that is not already 32 bytes (e.g. a random API
token), hash it through SHA3-256:

```rust
use threencr::TokenCrypt;

let tc = TokenCrypt::from_sha3("some-high-entropy-api-token");
```

### Recommended: Argon2id (passwords / low-entropy secrets)

For passwords or passphrases, use `TokenCrypt::from_argon2id`. It uses the
parameters recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf)
(`m=19456 KiB, t=2, p=1`). The salt must be at least 16 bytes.

```rust
use threencr::TokenCrypt;

let tc = TokenCrypt::from_argon2id(
    "correct horse battery staple",
    b"0123456789abcdef",
)?;
# Ok::<(), threencr::TokenCryptError>(())
```

### Legacy: PBKDF2-SHA3 (existing data only)

This crate does not implement the legacy PBKDF2-SHA3 KDF that earlier 3ncr.org
libraries (Go, Node.js, PHP, Java) shipped for backward compatibility. If you
need to decrypt data produced by that KDF, derive the 32-byte key with a
PBKDF2-SHA3-256 implementation (for example the `pbkdf2` crate with
`Sha3_256`) and pass the result to `from_raw_key`.

### Encrypt / decrypt

```rust
use threencr::TokenCrypt;

let tc = TokenCrypt::from_sha3("some-high-entropy-api-token");

let encrypted = tc.encrypt_3ncr("08019215-B205-4416-B2FB-132962F9952F");
// e.g. "3ncr.org/1#pHRu..."

let decrypted = tc.decrypt_if_3ncr(&encrypted)?;
# Ok::<(), threencr::TokenCryptError>(())
```

`decrypt_if_3ncr` returns its input unchanged (as `Cow::Borrowed`) when the
value does not start with the `3ncr.org/1#` header. This makes it safe to route
every configuration value through it regardless of whether it was encrypted.

Decryption failures (bad tag, truncated input, malformed base64) return a
`threencr::TokenCryptError`.

## Cross-implementation interop

This implementation decrypts the canonical v1 test vectors shared with the
[Go](https://github.com/3ncr/tokencrypt),
[Node.js](https://github.com/3ncr/nodencrypt),
[PHP](https://github.com/3ncr/tokencrypt-php), and
[Python](https://github.com/3ncr/tokencrypt-python) reference libraries. The
original 32-byte AES key was derived via PBKDF2-SHA3-256 with
`secret = "a"`, `salt = "b"`, `iterations = 1000`; this library only ships the
modern KDFs (raw key / SHA3-256 / Argon2id), so the test harness hardcodes the
derived key to verify envelope-level interop. See `tests/threencr.rs`.

## License

MIT — see [LICENSE](LICENSE).
