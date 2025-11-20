CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS ?= -lsodium

PROGS =       aead_chacha_ietf       aead_xchacha       aes256gcm_demo       secretbox_demo       box_demo       kx_demo       sign_demo       hash_and_mac       kdf_and_pwhash       rng_demo       secretstream_demo       init_only

all: $(PROGS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(PROGS)
