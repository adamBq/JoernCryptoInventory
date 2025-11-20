#include <sodium.h>
#include <string.h>
#include <stdio.h>
int main(void){
    if (sodium_init() < 0) return 1;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st_enc, st_dec;
    randombytes_buf(key, sizeof key);
    if (crypto_secretstream_xchacha20poly1305_init_push(&st_enc, header, key) != 0) return 1;
    const unsigned char m[] = "streaming message";
    unsigned char c[sizeof m + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned long long clen = 0;
    crypto_secretstream_xchacha20poly1305_push(&st_enc, c, &clen, m, sizeof m, NULL, 0, 0);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st_dec, header, key) != 0) return 1;
    unsigned char dec[sizeof m];
    unsigned long long mlen = 0;
    unsigned char tag;
    if (crypto_secretstream_xchacha20poly1305_pull(&st_dec, dec, &mlen, &tag, c, clen, NULL, 0) != 0) return 1;
    return 0;
}
