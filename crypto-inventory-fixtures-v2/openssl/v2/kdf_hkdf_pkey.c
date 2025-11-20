#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

int hkdf_pkey(const unsigned char *ikm, size_t ikmlen,
              const unsigned char *salt, size_t saltlen,
              const unsigned char *info, size_t infolen,
              unsigned char *okm, size_t *okmlen) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikmlen);
    EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen);
    EVP_PKEY_derive(pctx, okm, okmlen);
    EVP_PKEY_CTX_free(pctx);
    return 1;
}
