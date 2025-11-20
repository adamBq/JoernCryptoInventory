#include <sodium.h>
int main(void){
    if (sodium_init() < 0) return 1;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    const unsigned char m[] = "sign me";
    unsigned char sig[crypto_sign_BYTES];
    unsigned long long siglen;
    crypto_sign_detached(sig, &siglen, m, sizeof m, sk);
    if (crypto_sign_verify_detached(sig, m, sizeof m, pk) != 0) return 1;
    return 0;
}
