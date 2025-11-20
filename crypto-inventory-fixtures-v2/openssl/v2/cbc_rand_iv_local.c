#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

int aes_cbc_rand_iv_local(const unsigned char *pt, int ptlen,
                          const unsigned char *key,
                          unsigned char *ct) {
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv)); // local RAND source (should be detected as rand)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outlen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen);
    outlen += len;
    EVP_EncryptFinal_ex(ctx, ct + outlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    return outlen + len;
}
