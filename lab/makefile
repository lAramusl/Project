CC = gcc
CFLAGS = -Wall -fPIC # Add other CFLAGS you need
LDFLAGS = 
LIBS = 

CFLAGS += $(shell pkg-config --cflags openssl)
LIBS += $(shell pkg-config --libs openssl)

# Alternative for specific libraries if 'openssl' meta-package is not available:
# LIBS += $(shell pkg-config --libs libcrypto libssl)
# Example target
all: keygen program_a program_b

keygen: keygen.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

keygen.o: keygen.c
	$(CC) -c $(CFLAGS) $< -o $@

program_a: program_a.c
	$(CC) $^ -o client $(CFLAGS) $(LIBS)

program_b: program_b.c
	$(CC) $^ -o server $(CFLAGS) $(LIBS)

clean:
	rm -f *.o
	rm -f program_a program_b keygen

