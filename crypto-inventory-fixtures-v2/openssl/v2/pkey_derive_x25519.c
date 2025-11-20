#include <openssl/evp.h>
#include <openssl/params.h>

int x25519_kx(EVP_PKEY *priv, EVP_PKEY *peer, unsigned char *secret, size_t *secretlen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    EVP_PKEY_derive(ctx, secret, secretlen);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}
