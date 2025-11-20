#include <sodium.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) return 1;

    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    unsigned char ad[] = "associated-data";
    const unsigned char msg[] = "hello aead chacha20poly1305_ietf";
    unsigned char c[sizeof msg + crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned long long clen = 0;

    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);

    crypto_aead_chacha20poly1305_ietf_encrypt(
        c, &clen, msg, sizeof msg, ad, sizeof ad,
        NULL, nonce, key);

    unsigned char dec[sizeof msg];
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            dec, &mlen, NULL, c, clen, ad, sizeof ad, nonce, key) != 0) {
        return 1;
    }
    return 0;
}
