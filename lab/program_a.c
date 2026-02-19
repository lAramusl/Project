// program_a.c
// gcc program_a.c -o program_a -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#define PORT 4444
#define PUBKEY_LEN 32
#define SHARED_SECRET_LEN 32

#define SIG_LEN 64
#define ED25519_PUBKEY_LEN 32

#define AES_KEY_LEN 32
#define AES_IV_LEN 12
#define AES_TAG_LEN 16

#define TRANSCRIPT_HASH_LEN 32

#define HEADER_LEN 8
#define MAX_PAYLOAD 4096

void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY* load_private_key(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
        return NULL;

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    return pkey;
}

void derive_shared_secret(EVP_PKEY *privkey,
                          EVP_PKEY *peerkey,
                          unsigned char *secret,
                          size_t *secret_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) handle_errors();

    if (EVP_PKEY_derive_init(ctx) <= 0)
        handle_errors();

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0)
        handle_errors();

    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0)
        handle_errors();

    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0)
        handle_errors();

    EVP_PKEY_CTX_free(ctx);
}

// ===== HKDF + AES-256-GCM =====

// ================= HKDF =================

void derive_aes_key(const unsigned char *shared_secret,
                    size_t shared_secret_len,
                    unsigned char *aes_key)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx) handle_errors();

    if (EVP_PKEY_derive_init(kctx) <= 0)
        handle_errors();

    if (EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) <= 0)
        handle_errors();

    if (EVP_PKEY_CTX_set1_hkdf_salt(kctx,
                                    (unsigned char*)"salt",
                                    4) <= 0)
        handle_errors();

    if (EVP_PKEY_CTX_set1_hkdf_key(kctx,
                                   shared_secret,
                                   shared_secret_len) <= 0)
        handle_errors();

    if (EVP_PKEY_CTX_add1_hkdf_info(kctx,
                                    (unsigned char*)"handshake data",
                                    14) <= 0)
        handle_errors();

    size_t key_len = AES_KEY_LEN;

    if (EVP_PKEY_derive(kctx, aes_key, &key_len) <= 0)
        handle_errors();

    EVP_PKEY_CTX_free(kctx);
}

// ================= AES-GCM ENCRYPT =================

int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *key,
                    unsigned char *iv,
                    unsigned char *ciphertext,
                    unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    int len, ciphertext_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0)
        handle_errors();

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_IVLEN,
                            AES_IV_LEN,
                            NULL) <= 0)
        handle_errors();

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) <= 0)
        handle_errors();

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) <= 0)
            handle_errors();
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                          plaintext, plaintext_len) <= 0)
        handle_errors();

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0)
        handle_errors();

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_GET_TAG,
                            AES_TAG_LEN,
                            tag) <= 0)
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// ================= AES-GCM DECRYPT =================

int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *tag,
                    const unsigned char *key,
                    unsigned char *iv,
                    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    int len, plaintext_len, ret;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0)
        handle_errors();

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_IVLEN,
                            AES_IV_LEN,
                            NULL) <= 0)
        handle_errors();

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) <= 0)
        handle_errors();

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) <= 0)
            handle_errors();
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len,
                          ciphertext, ciphertext_len) <= 0)
        handle_errors();

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            AES_TAG_LEN,
                            (void*)tag) <= 0)
        handle_errors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1; // authentication failed
    }
}

// ===== SEQUENCE NUMBERS + TRANSCRIPT HASH (SHA-256) =====


// ================= TRANSCRIPT CONTEXT =================



// ================= SECURE SEND WITH SEQ + TRANSCRIPT =================

//Just one function to send and one function to recieve

EVP_PKEY* generate_x25519_key(void)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) handle_errors();

    if (EVP_PKEY_keygen_init(pctx) <= 0)
        handle_errors();

    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        handle_errors();

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}


int main(void)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // =============================
    // CLIENT SOCKET
    // =============================

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); exit(EXIT_FAILURE);
    }

    // --- Load ONLY private signing key ---
    EVP_PKEY *my_sign_key = load_private_key("ed25519_key_A.pem");
    if (!my_sign_key) {
        fprintf(stderr, "Signing key missing\n");
        exit(EXIT_FAILURE);
    }
    // --- Generate ephemeral X25519 ---
    EVP_PKEY *my_x25519 = generate_x25519_key();


    // =============================
    // HANDSHAKE
    // =============================

    
    // --- Derive shared secret ---

    printf("Handshake verified\n");

    // =============================
    // SECURE CHAT
    // =============================

    while (1)
    {

    }

    close(sock);

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}


