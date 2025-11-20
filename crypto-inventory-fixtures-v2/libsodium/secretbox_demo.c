#include <sodium.h>
int main(void){
    if (sodium_init() < 0) return 1;
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    const unsigned char m[] = "secretbox payload";
    unsigned char c[sizeof m + crypto_secretbox_MACBYTES];
    unsigned char dec[sizeof m];
    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);
    crypto_secretbox_easy(c, m, sizeof m, nonce, key);
    if (crypto_secretbox_open_easy(dec, c, sizeof c, nonce, key) != 0) return 1;
    return 0;
}
