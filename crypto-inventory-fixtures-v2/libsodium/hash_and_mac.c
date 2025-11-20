#include <sodium.h>
#include <string.h>
int main(void){
    if (sodium_init() < 0) return 1;
    const unsigned char m[] = "hash inputs";
    unsigned char h256[crypto_hash_sha256_BYTES];
    unsigned char h512[crypto_hash_sha512_BYTES];
    crypto_hash_sha256(h256, m, sizeof m);
    crypto_hash_sha512(h512, m, sizeof m);

    crypto_generichash_state st;
    unsigned char gh[crypto_generichash_BYTES];
    crypto_generichash_init(&st, NULL, 0, sizeof gh);
    crypto_generichash_update(&st, m, sizeof m);
    crypto_generichash_final(&st, gh, sizeof gh);

    unsigned char key[crypto_auth_hmacsha256_KEYBYTES];
    unsigned char tag[crypto_auth_hmacsha256_BYTES];
    randombytes_buf(key, sizeof key);
    crypto_auth_hmacsha256_state hst;
    crypto_auth_hmacsha256_init(&hst, key, sizeof key);
    crypto_auth_hmacsha256_update(&hst, m, sizeof m);
    crypto_auth_hmacsha256_final(&hst, tag);
    return 0;
}
