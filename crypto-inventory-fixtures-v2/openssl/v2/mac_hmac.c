#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>

int hmac_sha256(const unsigned char *key, int keylen,
                const unsigned char *msg, int msglen,
                unsigned char *out, unsigned int *outlen) {
    HMAC_CTX *hctx = HMAC_CTX_new();
    HMAC_Init_ex(hctx, key, keylen, EVP_sha256(), NULL);
    HMAC_Update(hctx, msg, msglen);
    HMAC_Final(hctx, out, outlen);
    HMAC_CTX_free(hctx);
    return 1;
}
