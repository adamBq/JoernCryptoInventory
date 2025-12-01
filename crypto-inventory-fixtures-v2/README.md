# OpenSSL + Libsodium Cryptographic Inventory 

This repo contains a Joern script and a set of small C test cases for exercising a **cryptographic bill of materials (CBOM)** pipeline across **OpenSSL** and **Libsodium** code utilising Joern.

The main entrypoint is:

- `opensslibsodium_cbom.sc`

and there are example input files under:

- `openssl/` – OpenSSL-style C fixtures  
- `libsodium/` – Libsodium-style C fixtures  

The script runs inside Joern’s Scala REPL and emits a **CycloneDX 1.6 CBOM** (`cbom.cdx.json`) with:

- Per-file components + SHA-256 hashes  
- Crypto/TLS components (algorithms, modes, providers, PQ metadata)  
- File-to-file **impact edges** (call graph edges) serialised into `impact.outbound.*` properties  

---

## Usage

Before running the scanner, [download and install Joern](https://docs.joern.io/installation/) and ensure the `joern` CLI is on your `PATH`.

1. Start the Joern shell:

   ```bash
   joern
   :load /abs/path/opensslibsodium_cbom.sc.sc
   workspace.reset
   importCode("/abs/path/<repo>")
   cryptoScan("/abs/path/<repo>", "/abs/path/cbom.cdx.json", ".*")
   ```
This will import the target repository into Joern, run the OpenSSL/Libsodium crypto scanner, and emit a cbom.cdx.json CycloneDX CBOM describing detected cryptographic usage and file-to-file impact edges.

## Features

### OpenSSL coverage

The script recognises and classifies (via regex + data-flow):

- **EVP creators**  
  - `EVP_EncryptInit_ex`, `EVP_DecryptInit_ex`, `EVP_CipherInit_ex`  
  - `EVP_DigestSignInit`, `EVP_DigestVerifyInit`, `EVP_DigestInit_ex`
- **Factories / selectors**
  - Ciphers: `EVP_aes_*`, `EVP_des_*`, `EVP_chacha20(_poly1305)`, `EVP_sm4_*`  
  - Digests: `EVP_sha*`, `EVP_shake*`, `EVP_blake2*`
  - Provider-world: `EVP_{CIPHER,MD,KDF,MAC}_fetch`
- **Creation / derivation path (optional pass)**
  - RNG: `RAND_bytes`, `RAND_priv_bytes`  
  - PBKDF: `PKCS5_PBKDF2_HMAC`  
  - KDF: `EVP_KDF_derive`  
  - Keygen: `EVP_PKEY_*keygen*`, `RSA_generate_key_ex`, `EC_KEY_generate_key`, `DH_generate_key`, `DSA_generate_key`  
  - PKEY derive/asym-enc: `EVP_PKEY_derive*`, `EVP_PKEY_encrypt*`, `EVP_PKEY_decrypt*`
- **MAC**
  - Classic HMAC / CMAC: `HMAC_*`, `CMAC_*`  
  - `EVP_MAC_*` (HMAC/CMAC via provider API)
- **TLS configuration**
  - `SSL_CTX_new`, `TLS_client_method`, `TLS_server_method`  
  - Version bounds: `SSL_CTX_set_min_proto_version`, `SSL_CTX_set_max_proto_version`  
  - Cipher suites/lists: `SSL_CTX_set_ciphersuites`, `SSL_CTX_set_cipher_list`  
  - Options: `SSL_CTX_set_options`  
  - Verification & trust: `SSL_CTX_set_verify`, `SSL_CTX_load_verify_locations`, `SSL_CTX_use_certificate_file`, `SSL_CTX_use_PrivateKey_file`  
  - Handshake use: `SSL_connect`, `SSL_accept`

AEAD (GCM/CCM/ChaCha20-Poly1305) support includes:

- **IV length**
- **Tag length**
- Presence of **AAD** (via `EVP_*Update` with `NULL` dest).

### Libsodium coverage

The script also fingerprints and classifies Libsodium usage, robust to Joern’s name/code normalisation:

- **AEAD**
  - `crypto_aead_{chacha20poly1305_ietf,xchacha20poly1305_ietf,aes256gcm}_*`
- **Secretbox**
  - `crypto_secretbox_*` (XSalsa20-Poly1305, treated as AEAD-like)
- **Box / KX / ECDH**
  - `crypto_box_*` (X25519 + XSalsa20-Poly1305)  
  - `crypto_kx_*`, `crypto_scalarmult*` (X25519 key exchange)
- **Signatures**
  - `crypto_sign*` (Ed25519)
- **Hash / MAC**
  - `crypto_hash_sha256/sha512`  
  - `crypto_generichash*` (BLAKE2b)  
  - `crypto_shorthash*` (SipHash)  
  - `crypto_auth*` (+ HMAC flavours)
- **KDF / PWHASH / RNG / Secretstream**
  - `crypto_pwhash(_argon2id)` (Argon2id)  
  - `crypto_kdf_derive_from_key`  
  - `randombytes_*`  
  - `crypto_secretstream_xchacha20poly1305_*`

For these families it infers:

- Algorithm (AES, CHACHA20-POLY1305, Ed25519, X25519, SHA256, BLAKE2b, SipHash, Argon2id, etc.)  
- Primitive: `aead`, `cipher`, `signature`, `hash`, `mac`, `kdf`, `rng`, `kx`  
- Mode & nonce length (e.g. 12 vs 24 byte nonces for AEAD / Secretstream)  
- PQ metadata (public-key vs symmetric; quantum-vulnerable / symmetric-safe / legacy-insecure)

### PQ / classical crypto metadata

For both OpenSSL and Libsodium, the script tags assets with:

- **PQ family detection** for OpenSSL provider world:
  - `ML-KEM` / Kyber, `ML-DSA` / Dilithium, `SLH-DSA` / SPHINCS+, `FN-DSA` / Falcon, etc.  
- Classical public-key:
  - RSA, ECDSA, Ed25519, X25519  
- Symmetric vs hash vs KDF classification  
- PQ-relevant vulnerability tag:
  - `post-quantum-safe`, `quantum-vulnerable`, `symmetric-safe`, `legacy-insecure`, `unknown`
- Weakness tags:
  - e.g. `DES-legacy`, `3DES-legacy`, `RC4-legacy`, `MD5-weak`, `SHA1-weak`, `ECB-insecure`, `CBC-check-iv-source`

### Data-flow & impact edges

The script uses Joern data-flow where available to:

- Resolve **factory/selector calls** behind `EVP_*Init` arguments  
- Infer **key type and origin** for `EVP_DigestSignInit` / `EVP_DigestVerifyInit`:
  - RSA vs ECDSA vs Ed25519 vs X25519 vs OpenSSL PQ families  
  - Whether keys are from PEM / DER vs locally generated (`key.origin`)  
  - EC curve where possible (`key.curve` like P-256/P-384/P-521)
- Classify IV/nonce source (`ivSource`):
  - `rand`, `memset-zero`, `calloc-zero`, `bzero`, `zero-literal`, `null`, `unknown`

It also builds **file-to-file impact edges**:

- Strict, intra-repo edges only:
  - Both caller and callee are non-external  
  - Both files are “real” (no `<unknown>` virtuals)  
  - Source and destination files differ  
- These are attached to each file component via:
  - `impact.outbound.count` (distinct outbound files)  
  - `impact.outbound.edges` (JSON blob of individual edges)

---
