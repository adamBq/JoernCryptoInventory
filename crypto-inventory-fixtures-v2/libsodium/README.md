# Libsodium Fixture for CBOM/DF Testing

This sample folder contains small C programs that call many Libsodium APIs so your Joern-based CBOM + dataflow script can detect:

- AEAD: chacha20poly1305 (IETF), xchacha20poly1305, aes256gcm (if available)
- Secretbox (XSalsa20-Poly1305)
- Public-key box (Curve25519/X25519 + XSalsa20-Poly1305)
- KX: crypto_kx client/server session keys
- Signatures: Ed25519
- Hashes: SHA-256/SHA-512, crypto_generichash (BLAKE2b), crypto_shorthash (SipHash)
- MAC/Auth: crypto_auth_hmacsha256/512
- KDF: crypto_kdf_derive_from_key; PWHASH (Argon2id)
- RNG: randombytes_buf, randombytes_uniform
- Secretstream (xchacha20poly1305)

## Build (optional — the analysis doesn't need to build)
You only need headers for `#include <sodium.h>`. To build:

```bash
cc -O2 -Wall -Wextra -o aead_chacha_ietf aead_chacha_ietf.c -lsodium
# etc…
```

## Joern usage
In your Joern shell:
```scala
importCode("/mnt/data/libsodium-fixture")
openSslCbomDF("/mnt/data/libsodium-fixture", "/mnt/data/libsodium-fixture/cbom.cdx.json", ".*")
```

Your writer will emit provider `Libsodium` for these calls.
