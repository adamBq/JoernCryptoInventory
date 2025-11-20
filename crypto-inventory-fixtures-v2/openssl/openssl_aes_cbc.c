#include <openssl/evp.h>
#include <string.h>
int encrypt_cbc(const unsigned char *pt, int ptlen,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ct) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len=0, ctlen=0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen); ctlen += len;
    EVP_EncryptFinal_ex(ctx, ct+ctlen, &len); ctlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return ctlen;
}
