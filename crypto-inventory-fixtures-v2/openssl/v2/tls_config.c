#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <string.h>

int tls_client_demo(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, 0); // allow max
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL);
    SSL *ssl = SSL_new(ctx);
    // SSL_connect(ssl); // Uncomment to flag role=client
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
}

int tls_server_demo(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    SSL *ssl = SSL_new(ctx);
    // SSL_accept(ssl); // Uncomment to flag role=server
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
}
