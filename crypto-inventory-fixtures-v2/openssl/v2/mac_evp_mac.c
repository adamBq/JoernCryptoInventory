#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string.h>

int evp_mac_hmac_api(const unsigned char *key, size_t keylen,
                     const unsigned char *msg, size_t msglen,
                     unsigned char *out, size_t *outlen) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", "provider=default");
    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(mctx, key, keylen, params);
    EVP_MAC_update(mctx, msg, msglen);
    EVP_MAC_final(mctx, out, outlen, 64);

    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    return 1;
}
