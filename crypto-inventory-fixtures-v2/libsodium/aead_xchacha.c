#include <sodium.h>

#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) return 1;

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    const unsigned char m[] = "xchacha20poly1305 aead message";
    const unsigned char ad[] = "aad-present";
    unsigned char c[sizeof m + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long clen = 0;
    unsigned char dec[sizeof m];
    unsigned long long mlen = 0;

    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        c, &clen, m, sizeof m, ad, sizeof ad, NULL, nonce, key);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            dec, &mlen, NULL, c, clen, ad, sizeof ad, nonce, key) != 0) return 1;
    return 0;
}
