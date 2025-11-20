#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

int rsa_oaep_encrypt(EVP_PKEY *pkey, const unsigned char *in, size_t inlen,
                     unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int rsa_pkcs1v15_decrypt(EVP_PKEY *pkey, const unsigned char *in, size_t inlen,
                         unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}
