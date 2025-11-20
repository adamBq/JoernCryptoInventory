#include <sodium.h>
#include <stdio.h>
int main(void){
    if (sodium_init() < 0) return 1;
    unsigned char pkc[crypto_kx_PUBLICKEYBYTES], skc[crypto_kx_SECRETKEYBYTES];
    unsigned char pks[crypto_kx_PUBLICKEYBYTES], sks[crypto_kx_SECRETKEYBYTES];
    unsigned char rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char ry[crypto_kx_SESSIONKEYBYTES], ty[crypto_kx_SESSIONKEYBYTES];
    crypto_kx_keypair(pkc, skc);
    crypto_kx_keypair(pks, sks);
    if (crypto_kx_client_session_keys(rx, tx, pkc, skc, pks) != 0) return 1;
    if (crypto_kx_server_session_keys(ry, ty, pks, sks, pkc) != 0) return 1;
    return 0;
}
