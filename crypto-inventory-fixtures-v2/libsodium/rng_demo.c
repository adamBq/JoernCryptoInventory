#include <sodium.h>
#include <stdio.h>
int main(void){
    if (sodium_init() < 0) return 1;
    unsigned char buf[32];
    randombytes_buf(buf, sizeof buf);
    (void) randombytes_uniform(1000);
    return 0;
}
