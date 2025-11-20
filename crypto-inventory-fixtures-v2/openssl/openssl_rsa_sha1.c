#include <openssl/evp.h>
int sign_sha1(EVP_PKEY *pkey, const unsigned char *msg, size_t msglen,
              unsigned char *sig, size_t *siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey);
    EVP_DigestSignUpdate(mdctx, msg, msglen);
    EVP_DigestSignFinal(mdctx, sig, siglen);
    EVP_MD_CTX_free(mdctx);
    return 0;
}
