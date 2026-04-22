# tokencrypt (3ncr.org)

Rust implementation of the [3ncr.org](https://3ncr.org/) v1 string encryption
standard.

3ncr.org is a small, interoperable format for encrypted strings, originally
intended for encrypting tokens in configuration files but usable for any UTF-8
string. v1 uses AES-256-GCM with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

## Install

```toml
[dependencies]
tokencrypt = "1"
```

Requires Rust 1.74+.

## Usage

Pick a constructor based on the entropy of your secret.

### Recommended: Argon2id (low-entropy secrets)

For passwords or passphrases, use `TokenCrypt::from_argon2id`. It uses the
parameters recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf)
(m=19456 KiB, t=2, p=1). Salt must be at least 16 bytes.

```rust
use tokencrypt::TokenCrypt;

let tc = TokenCrypt::from_argon2id(
    "correct horse battery staple",
    b"0123456789abcdef",
)?;
# Ok::<(), tokencrypt::TokenCryptError>(())
```

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key, skip the KDF and pass it directly.

```rust
use tokencrypt::TokenCrypt;

let mut key = [0u8; 32];
getrandom::getrandom(&mut key).expect("system RNG");
let tc = TokenCrypt::from_raw_key(key);
```

For a high-entropy secret that is not already 32 bytes (e.g. a random API
token), hash it through SHA3-256:

```rust
use tokencrypt::TokenCrypt;

let tc = TokenCrypt::from_sha3("some-high-entropy-api-token");
```

### Legacy: PBKDF2-SHA3

The original `(secret, salt, iterations)` KDF is kept for backward compatibility
with data encrypted by earlier 3ncr.org libraries. It is **deprecated** — prefer
`from_argon2id`, `from_raw_key`, or `from_sha3` for new code.

```rust
# #[allow(deprecated)]
# {
use tokencrypt::TokenCrypt;

let tc = TokenCrypt::from_pbkdf2_sha3("my-secret", "my-salt", 1000);
# }
```

### Encrypt / decrypt

```rust
use tokencrypt::TokenCrypt;

let tc = TokenCrypt::from_sha3("some-high-entropy-api-token");

let encrypted = tc.encrypt_3ncr("08019215-B205-4416-B2FB-132962F9952F");
// e.g. "3ncr.org/1#pHRu..."

let decrypted = tc.decrypt_if_3ncr(&encrypted)?;
# Ok::<(), tokencrypt::TokenCryptError>(())
```

`decrypt_if_3ncr` returns its input unchanged (as `Cow::Borrowed`) when the
value does not start with the `3ncr.org/1#` header. This makes it safe to route
every configuration value through it regardless of whether it was encrypted.

Decryption failures (bad tag, truncated input, malformed base64) return a
`tokencrypt::TokenCryptError`.

## Cross-implementation interop

This implementation decrypts the canonical v1 test vectors shared with the
[Go](https://github.com/3ncr/tokencrypt),
[Node.js](https://github.com/3ncr/nodencrypt),
[PHP](https://github.com/3ncr/tokencrypt-php), and
[Python](https://github.com/3ncr/tokencrypt-python) reference libraries
(`secret = "a"`, `salt = "b"`, `iterations = 1000`). See
`tests/tokencrypt.rs`.

## License

MIT
