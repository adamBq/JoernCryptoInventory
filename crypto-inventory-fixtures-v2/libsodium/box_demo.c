#include <sodium.h>
#include <string.h>
int main(void){
    if (sodium_init() < 0) return 1;
    unsigned char pk1[crypto_box_PUBLICKEYBYTES], sk1[crypto_box_SECRETKEYBYTES];
    unsigned char pk2[crypto_box_PUBLICKEYBYTES], sk2[crypto_box_SECRETKEYBYTES];
    unsigned char nonce[crypto_box_NONCEBYTES];
    const unsigned char msg[] = "box easy demo";
    unsigned char c[sizeof msg + crypto_box_MACBYTES];
    unsigned char dec[sizeof msg];
    crypto_box_keypair(pk1, sk1);
    crypto_box_keypair(pk2, sk2);
    randombytes_buf(nonce, sizeof nonce);
    crypto_box_easy(c, msg, sizeof msg, nonce, pk2, sk1);
    if (crypto_box_open_easy(dec, c, sizeof c, nonce, pk1, sk2) != 0) return 1;
    // precompute path (beforenm) to exercise derive
    unsigned char k[crypto_box_BEFORENMBYTES];
    crypto_box_beforenm(k, pk2, sk1);
    return 0;
}
