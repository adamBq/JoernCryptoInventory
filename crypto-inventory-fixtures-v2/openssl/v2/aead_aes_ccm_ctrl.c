#include <openssl/evp.h>
#include <string.h>

int aes_ccm_encrypt(const unsigned char *pt, int ptlen,
                    const unsigned char *aad, int aadlen,
                    const unsigned char *key,
                    const unsigned char *iv,
                    unsigned char *ct, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outlen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, tag);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen);
    EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen);
    outlen += len;
    EVP_EncryptFinal_ex(ctx, ct + outlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    return outlen + len;
}
