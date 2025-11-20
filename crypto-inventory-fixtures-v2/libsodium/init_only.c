#include <sodium.h>
int main(void) { return sodium_init() < 0 ? 1 : 0; }
