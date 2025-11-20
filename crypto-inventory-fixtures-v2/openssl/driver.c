#include <string.h>
int encrypt_cbc(const unsigned char *pt, int ptlen,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ct);
int insecure_iv(unsigned char *iv, int n);
int demo_driver() {
    unsigned char key[16] = {0};
    unsigned char pt[32] = "hello world";
    unsigned char ct[64];
    unsigned char iv_static[16] = {0}; // static IV
    int n1 = encrypt_cbc(pt, 11, key, iv_static, ct);
    unsigned char iv_rand[16];
    insecure_iv(iv_rand, 16); // IV from rand() helper
    int n2 = encrypt_cbc(pt, 11, key, iv_rand, ct);
    return n1 + n2;
}
