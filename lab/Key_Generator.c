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

EVP_PKEY* generate_ed25519_key(void)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) handle_errors();

    if (EVP_PKEY_keygen_init(pctx) <= 0)
        handle_errors();

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        handle_errors();

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

void write_private_key(const char *filename, EVP_PKEY *pkey)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL))
        handle_errors();

    fclose(fp);
}

int main(void)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_PKEY *key1 = generate_ed25519_key();
    EVP_PKEY *key2 = generate_ed25519_key();

    write_private_key("ed25519_key_A.pem", key1);
    write_private_key("ed25519_key_B.pem", key2);

    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
