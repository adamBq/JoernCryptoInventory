#include <openssl/evp.h>
const EVP_CIPHER* pick_cipher(int bits, int gcm);
int encrypt_via_wrapper(const unsigned char *pt, int ptlen,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char *ct, int bits, int gcm) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len=0, ctlen=0;
    const EVP_CIPHER* algo = pick_cipher(bits, gcm);
    EVP_EncryptInit_ex(ctx, algo, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen); ctlen += len;
    EVP_EncryptFinal_ex(ctx, ct+ctlen, &len); ctlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return ctlen;
}
