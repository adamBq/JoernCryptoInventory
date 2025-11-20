#include <openssl/evp.h>
const EVP_MD* choose_digest(int weak) {
    return weak ? EVP_sha1() : EVP_sha256();
}
int sign_with_choice(EVP_PKEY *pkey, const unsigned char *msg, size_t msglen,
                     unsigned char *sig, size_t *siglen, int weak) {
    const EVP_MD *md = choose_digest(weak);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey);
    EVP_DigestSignUpdate(mdctx, msg, msglen);
    EVP_DigestSignFinal(mdctx, sig, siglen);
    EVP_MD_CTX_free(mdctx);
    return 0;
}
