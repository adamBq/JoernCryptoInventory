#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

int rng_pbkdf2_demo(const unsigned char *pw, size_t pwlen,
                    const unsigned char *salt, size_t saltlen,
                    unsigned char *key, int keylen) {
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf)); // RNG site
    PKCS5_PBKDF2_HMAC((const char*)pw, (int)pwlen, salt, (int)saltlen, 10000, EVP_sha256(), keylen, key);
    return 1;
}
