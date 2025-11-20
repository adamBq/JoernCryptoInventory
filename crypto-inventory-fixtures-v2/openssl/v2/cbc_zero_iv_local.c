#include <openssl/evp.h>
#include <string.h>

int aes_cbc_zero_iv_local(const unsigned char *pt, int ptlen,
                          const unsigned char *key,
                          unsigned char *ct) {
    unsigned char iv[16] = {0}; // local zero-literal IV (should be detected)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outlen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen);
    outlen += len;
    EVP_EncryptFinal_ex(ctx, ct + outlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    return outlen + len;
}
