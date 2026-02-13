#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define MSG_MAX 512

void load_key(const char *file, unsigned char *key, size_t len) {
    FILE *f = fopen(file, "rb");
    if (!f) { perror(file); exit(1); }
    fread(key, 1, len, f);
    fclose(f);
}

void append_transcript(const char *file, const char *msg) {
    FILE *f = fopen(file, "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// Generates both Identity (Ed) and Exchange (X) keys
void generate_all_keys(const char* folder, const char* prefix) {
    char priv_path[128], pub_path[128];
    
    // Ed25519
    sprintf(priv_path, "%s/%s_ed_priv", folder, prefix);
    sprintf(pub_path, "%s/%s_ed_pub", folder, prefix);
    if (access(priv_path, F_OK) == -1) {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_keypair(pk, sk);
        FILE *f1 = fopen(priv_path, "wb"); fwrite(sk, 1, sizeof sk, f1); fclose(f1);
        FILE *f2 = fopen(pub_path, "wb");  fwrite(pk, 1, sizeof pk, f2); fclose(f2);
    }
}

#endif
