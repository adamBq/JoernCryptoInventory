#include <openssl/evp.h>
const EVP_CIPHER* pick_cipher(int bits, int gcm) {
    if (gcm) return bits==256 ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    return bits==256 ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
}
