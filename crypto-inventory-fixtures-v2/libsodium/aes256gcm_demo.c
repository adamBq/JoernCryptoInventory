#include <sodium.h>
#include <stdio.h>
// This compiles even if runtime HW support is absent; function exists if not minimal build.
int main(void) {
    if (sodium_init() < 0) return 1;
//#ifdef crypto_aead_aes256gcm_KEYBYTES
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES];
    const unsigned char msg[] = "aes256gcm via libsodium";
    const unsigned char ad[] = "aad";
    unsigned char c[sizeof msg + crypto_aead_aes256gcm_ABYTES];
    unsigned long long clen = 0;
    randombytes_buf(key, sizeof key);
    randombytes_buf(npub, sizeof npub);
    if (crypto_aead_aes256gcm_is_available()) {
        crypto_aead_aes256gcm_encrypt(c, &clen, msg, sizeof msg, ad, sizeof ad, NULL, npub, key);
    }
//#endif
    return 0;
}
