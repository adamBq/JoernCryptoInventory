#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <string.h>

int cmac_aes128(const unsigned char *key, int keylen,
                const unsigned char *msg, size_t msglen,
                unsigned char *out, size_t *outlen) {
    CMAC_CTX *c = CMAC_CTX_new();
    CMAC_Init(c, key, keylen, EVP_aes_128_cbc(), NULL);
    CMAC_Update(c, msg, msglen);
    CMAC_Final(c, out, outlen);
    CMAC_CTX_free(c);
    return 1;
}
