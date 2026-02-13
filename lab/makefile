CC = gcc
CFLAGS = -Wall -fPIC # Add other CFLAGS you need
LDFLAGS = 
LIBS = 

CFLAGS += $(shell pkg-config --cflags openssl)
LIBS += $(shell pkg-config --libs openssl)

# Alternative for specific libraries if 'openssl' meta-package is not available:
# LIBS += $(shell pkg-config --libs libcrypto libssl)
# Example target
keygenerator: keygenerator.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

keygenerator.o: Key_Generator.c
	$(CC) -c $(CFLAGS) $< -o $@

program_a: program_a.c
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

program_b: program_b.c
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o
