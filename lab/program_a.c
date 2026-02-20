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

void make_nonce(unsigned char *nonce,
                const unsigned char *static_iv,
                uint64_t seq)
{
    memcpy(nonce, static_iv, AES_IV_LEN);

    uint64_t seq_be = htobe64(seq);

    for (int i = 0; i < 8; i++) {
        nonce[4 + i] ^= ((unsigned char*)&seq_be)[i];
    }
}

void compute_finished(const unsigned char *finished_key,
                      const unsigned char *transcript_hash,
                      unsigned char *out)
{
    unsigned int len;
    HMAC(EVP_sha256(),
         finished_key, 32,
         transcript_hash, 32,
         out, &len);
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
// 1. VERSION & CIPHER NEGOTIATION (add before key exchange)
typedef struct {
    uint16_t version;        // e.g., 0x0304 for TLS 1.3
    uint16_t cipher_suite;   // e.g., 0x1301 for AES_256_GCM_SHA384
} handshake_hello_t;

// 2. SECURE SEND FUNCTION
void secure_send(int sock, const unsigned char *data, size_t len, 
                 const unsigned char *key, uint32_t *seq) {
    unsigned char iv[AES_IV_LEN];
    unsigned char ciphertext[MAX_PAYLOAD];
    unsigned char tag[AES_TAG_LEN];
    
    // Generate random IV
    make_nonce(iv, client_iv, *seq);
    
    // Encrypt with sequence number as AAD
    int cipher_len = aes_gcm_encrypt(data, len, (unsigned char*)seq, 4, 
                                     key, iv, ciphertext, tag);
    
    // Send: IV + ciphertext + tag
    send(sock, iv, AES_IV_LEN, 0);
    send(sock, ciphertext, cipher_len, 0);
    send(sock, tag, AES_TAG_LEN, 0);
    
    (*seq)++;
}

// 3. SECURE RECEIVE FUNCTION  
void secure_receive(int sock, unsigned char *data, size_t expected_len,
                    const unsigned char *key, uint32_t *seq) {
    unsigned char iv[AES_IV_LEN];
    unsigned char ciphertext[MAX_PAYLOAD];
    unsigned char tag[AES_TAG_LEN];
    
    make_nonce(iv, server_iv, *seq);

    recv(sock, iv, AES_IV_LEN, 0);
    recv(sock, ciphertext, expected_len, 0);  
    recv(sock, tag, AES_TAG_LEN, 0);
    
    if (aes_gcm_decrypt(ciphertext, expected_len, (unsigned char*)seq, 4,
                        tag, key, iv, data) < 0) {
        fprintf(stderr, "Decryption failed!\n");
        exit(EXIT_FAILURE);
    }
    
    (*seq)++;
}
//Just one function to send and one function to recieve
void hkdf_expand(const unsigned char *secret,
                 size_t secret_len,
                 const char *label,
                 unsigned char *out,
                 size_t out_len)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(kctx);
    EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(kctx, secret, secret_len);
    EVP_PKEY_CTX_add1_hkdf_info(kctx,
                                (unsigned char*)label,
                                strlen(label));
    EVP_PKEY_derive(kctx, out, &out_len);
    EVP_PKEY_CTX_free(kctx);
}

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

EVP_MD_CTX *transcript_ctx;

void transcript_init()
{
    transcript_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(transcript_ctx, EVP_sha256(), NULL);
}

void transcript_update(const void *data, size_t len)
{
    EVP_DigestUpdate(transcript_ctx, data, len);
}

void transcript_final(unsigned char *out)
{
    EVP_DigestFinal_ex(transcript_ctx, out, NULL);
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

    transcript_init();

    handshake_hello_t ch;
    ch.version = htons(0x0304);
    ch.cipher_suite = htons(0x1301);

    send(sock, &ch, sizeof(ch), 0);
    transcript_update(&ch, sizeof(ch));

    handshake_hello_t sh;
    recv(sock, &sh, sizeof(sh), 0);
    transcript_update(&sh, sizeof(sh));
    if (ntohs(sh.version) != 0x0304)
    {
        printf("Version mismatch\n");
        exit(EXIT_FAILURE);
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

    

    // --- Client ephemeral X25519 public key ---
    unsigned char my_pub[PUBKEY_LEN];
    size_t pub_len = PUBKEY_LEN;
    EVP_PKEY_get_raw_public_key(my_x25519, my_pub, &pub_len);

    // --- Client signing public key ---
    unsigned char my_sign_pub[ED25519_PUBKEY_LEN];
    size_t spub_len = ED25519_PUBKEY_LEN;
    EVP_PKEY_get_raw_public_key(my_sign_key, my_sign_pub, &spub_len);

    // --- Send client ephemeral + signing keys ---
    send(sock, my_pub, PUBKEY_LEN, 0);
    send(sock, my_sign_pub, ED25519_PUBKEY_LEN, 0);

    // --- Sign client ephemeral key ---
    unsigned char signature[SIG_LEN];
    size_t sig_len = SIG_LEN;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();
    
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, my_sign_key) <= 0)
        handle_errors();
    unsigned char temp_hash[32];
    EVP_MD_CTX *tmp = EVP_MD_CTX_new();
    EVP_DigestInit_ex(tmp, EVP_sha256(), NULL);
    EVP_DigestUpdate(tmp, my_pub, PUBKEY_LEN);
    EVP_DigestFinal_ex(tmp, temp_hash, NULL);
    EVP_MD_CTX_free(tmp);

    EVP_DigestSign(mdctx, signature, &sig_len, temp_hash, 32);
    transcript_update(my_pub, PUBKEY_LEN);
    transcript_update(my_sign_pub, ED25519_PUBKEY_LEN);
    transcript_update(signature, SIG_LEN);

    send(sock, signature, SIG_LEN, 0);

    // --- Receive server ephemeral, signing keys and signature ---
    unsigned char server_pub[PUBKEY_LEN];
    unsigned char server_sign_pub[ED25519_PUBKEY_LEN];
    unsigned char server_sig[SIG_LEN];

    recv(sock, server_pub, PUBKEY_LEN, 0);
    recv(sock, server_sign_pub, ED25519_PUBKEY_LEN, 0);
    recv(sock, server_sig, SIG_LEN, 0);

    transcript_update(server_pub, PUBKEY_LEN);
    transcript_update(server_sign_pub, ED25519_PUBKEY_LEN);
    transcript_update(server_sig, SIG_LEN);

    // --- Build server Ed25519 public key for signature verification ---
    EVP_PKEY *server_sign_key = 
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, server_sign_pub, ED25519_PUBKEY_LEN);
    if (!server_sign_key) handle_errors();

    // --- Verify server signature ---
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();
    
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, server_sign_key) <= 0)
        handle_errors();
    if (EVP_DigestVerify(mdctx, server_sig, SIG_LEN, server_pub, PUBKEY_LEN) <= 0) {
        fprintf(stderr, "Server authentication failed!\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(mdctx);

    // --- Build server X25519 public key ---
    EVP_PKEY *server_x25519 =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pub, PUBKEY_LEN);
    if (!server_x25519) handle_errors();

    // --- Derive shared secret ---
    unsigned char shared_secret[SHARED_SECRET_LEN];
    size_t ss_len = SHARED_SECRET_LEN;
    derive_shared_secret(my_x25519, server_x25519, shared_secret, &ss_len);

    // --- Derive AES key for secure chat ---
    unsigned char aes_key[AES_KEY_LEN];
    unsigned char client_key[32];
    unsigned char server_key[32];
    unsigned char client_iv[12];
    unsigned char server_iv[12];
    unsigned char client_finished_key[32];
    unsigned char server_finished_key[32];

    hkdf_expand(shared_secret, ss_len, "client key", client_key, 32);
    hkdf_expand(shared_secret, ss_len, "server key", server_key, 32);
    hkdf_expand(shared_secret, ss_len, "client iv", client_iv, 12);
    hkdf_expand(shared_secret, ss_len, "server iv", server_iv, 12);
    hkdf_expand(shared_secret, ss_len, "client finished", client_finished_key, 32);
    hkdf_expand(shared_secret, ss_len, "server finished", server_finished_key, 32);

    unsigned char transcript_hash[32];
    transcript_final(transcript_hash);

    unsigned char my_finished[32];
    compute_finished(client_finished_key, transcript_hash, my_finished);

    send(sock, my_finished, 32, 0);

    unsigned char server_finished[32];
    recv(sock, server_finished, 32, 0);

    unsigned char expected[32];
    compute_finished(server_finished_key, transcript_hash, expected);

    if (memcmp(expected, server_finished, 32) != 0) {
        printf("Finished verify failed\n");
        exit(EXIT_FAILURE);
    }

    printf("[Handshake] Finished: AES key established\n");
   

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

