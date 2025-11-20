#include <sodium.h>
#include <string.h>
int main(void){
    if (sodium_init() < 0) return 1;
    // crypto_kdf_derive_from_key
    unsigned char master[crypto_kdf_KEYBYTES];
    unsigned char sub[32];
    randombytes_buf(master, sizeof master);
    crypto_kdf_keygen(master);
    crypto_kdf_derive_from_key(sub, sizeof sub, 7, "CTXCTX01", master);

    // crypto_pwhash (Argon2id) — parameters captured by DF if you extend it
    const char *password = "correct horse battery staple";
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char out[32];
    randombytes_buf(salt, sizeof salt);
    if (crypto_pwhash(out, sizeof out, password, strlen(password), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) return 1;
    return 0;
}
