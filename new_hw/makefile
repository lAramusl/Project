CC     = gcc
CFLAGS = -Wall -Wextra $(shell pkg-config --cflags openssl)
LIBS   = $(shell pkg-config --libs openssl)

all: server_tap client_tap device_x device_y keys

server_tap: server_tap.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

client_tap: client_tap.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

device_x: device_x.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

device_y: device_y.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

keys:
	openssl genpkey -algorithm Ed25519 -out server_priv.pem
	openssl genpkey -algorithm Ed25519 -out client_priv.pem
	openssl pkey -in server_priv.pem -pubout -out server_pub.pem
	openssl pkey -in client_priv.pem -pubout -out client_pub.pem

clean:
	rm -f server_tap client_tap device_x device_y
	rm -f server_priv.pem server_pub.pem client_priv.pem client_pub.pem

.PHONY: all keys clean