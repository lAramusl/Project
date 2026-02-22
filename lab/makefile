CC     = gcc
CFLAGS = -Wall -Wextra $(shell pkg-config --cflags openssl)
LIBS   = $(shell pkg-config --libs openssl)

all: keygen server client

keygen: keygen.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

server: program_b.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

client: program_a.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

keys: keygen
	./keygen

clean:
	rm -f keygen server client *.o
	rm -f ed25519_key_A.pem ed25519_key_A_pub.pem \
	      ed25519_key_B.pem ed25519_key_B_pub.pem

.PHONY: all keys clean