// keygen.c
// gcc keygen.c -o keygen -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY *generate_ed25519_key(void)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) handle_errors();

    if (EVP_PKEY_keygen_init(pctx) <= 0)
        handle_errors();

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        handle_errors();

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

void write_private_key(const char *filename, EVP_PKEY *pkey)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp) { perror(filename); exit(EXIT_FAILURE); }
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL))
        handle_errors();
    fclose(fp);
    printf("[keygen] Wrote private key: %s\n", filename);
}

void write_public_key(const char *filename, EVP_PKEY *pkey)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp) { perror(filename); exit(EXIT_FAILURE); }
    if (!PEM_write_PUBKEY(fp, pkey))
        handle_errors();
    fclose(fp);
    printf("[keygen] Wrote public  key: %s\n", filename);
}

int main(void)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Client (A) keypair
    EVP_PKEY *key_A = generate_ed25519_key();
    // Server (B) keypair
    EVP_PKEY *key_B = generate_ed25519_key();

    // Private keys (each side keeps its own)
    write_private_key("ed25519_key_A.pem",     key_A);
    write_private_key("ed25519_key_B.pem",     key_B);

    // Public keys (each side shares its OWN public key so the other can verify)
    write_public_key("ed25519_key_A_pub.pem",  key_A);   // server loads this to verify client
    write_public_key("ed25519_key_B_pub.pem",  key_B);   // client loads this to verify server

    EVP_PKEY_free(key_A);
    EVP_PKEY_free(key_B);

    EVP_cleanup();
    ERR_free_strings();

    printf("\n[keygen] All keys generated successfully.\n");
    printf("         Run ./server first, then ./client\n");
    return 0;
}