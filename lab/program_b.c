// program_b.c  — SERVER
// Receives encrypted messages from the client.
// Build: gcc program_b.c -o server -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define PORT              4444
#define PUBKEY_LEN        32
#define SHARED_SECRET_LEN 32
#define SIG_LEN           64
#define AES_IV_LEN        12
#define AES_TAG_LEN       16
#define MAX_PAYLOAD       4096

/* ── Handshake hello ───────────────────────────────────────────── */
typedef struct {
    uint16_t version;       // 0x0304
    uint16_t cipher_suite;  // 0x1301
} handshake_hello_t;

/* ── Error handling ────────────────────────────────────────────── */
void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/* ── Key loading ───────────────────────────────────────────────── */
EVP_PKEY *load_private_key(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open private key: %s\n", filename);
        exit(EXIT_FAILURE);
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "[ERROR] Failed to parse private key: %s\n", filename);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return pkey;
}

EVP_PKEY *load_public_key(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "[ERROR] Cannot open public key: %s\n", filename);
        exit(EXIT_FAILURE);
    }
    EVP_PKEY *key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!key) {
        fprintf(stderr, "[ERROR] Failed to parse public key: %s\n", filename);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return key;
}

/* ── X25519 keygen ─────────────────────────────────────────────── */
EVP_PKEY *generate_x25519_key(void)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) handle_errors();
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_errors();
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handle_errors();
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/* ── ECDH ──────────────────────────────────────────────────────── */
void derive_shared_secret(EVP_PKEY *privkey, EVP_PKEY *peerkey,
                           unsigned char *secret, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) handle_errors();
    if (EVP_PKEY_derive_init(ctx) <= 0) handle_errors();
    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) handle_errors();
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) handle_errors();
    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) handle_errors();
    EVP_PKEY_CTX_free(ctx);
}

/* ── HKDF expand ───────────────────────────────────────────────── */
void hkdf_expand(const unsigned char *secret, size_t secret_len,
                 const unsigned char *salt,   size_t salt_len,
                 const char *label,
                 unsigned char *out,          size_t out_len)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx) handle_errors();
    if (EVP_PKEY_derive_init(kctx) <= 0) handle_errors();
    if (EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) <= 0) handle_errors();
    if (EVP_PKEY_CTX_set1_hkdf_salt(kctx, salt, salt_len) <= 0) handle_errors();
    if (EVP_PKEY_CTX_set1_hkdf_key(kctx, secret, secret_len) <= 0) handle_errors();
    if (EVP_PKEY_CTX_add1_hkdf_info(kctx,
            (const unsigned char*)label, strlen(label)) <= 0) handle_errors();
    if (EVP_PKEY_derive(kctx, out, &out_len) <= 0) handle_errors();
    EVP_PKEY_CTX_free(kctx);
}

/* ── Nonce construction ────────────────────────────────────────── */
void make_nonce(unsigned char *nonce, const unsigned char *static_iv, uint64_t seq)
{
    memcpy(nonce, static_iv, AES_IV_LEN);
    uint64_t seq_be = htobe64(seq);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= ((unsigned char*)&seq_be)[i];
}

/* ── Finished MAC ──────────────────────────────────────────────── */
void compute_finished(const unsigned char *finished_key,
                      const unsigned char *transcript_hash,
                      unsigned char *out)
{
    unsigned int len;
    HMAC(EVP_sha256(), finished_key, 32, transcript_hash, 32, out, &len);
}

/* ── AES-256-GCM decrypt ───────────────────────────────────────── */
int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *aad,         int aad_len,
                    const unsigned char *tag,
                    const unsigned char *key,
                    unsigned char       *iv,
                    unsigned char       *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    int len, plaintext_len, ret;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) handle_errors();
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL) <= 0) handle_errors();
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) <= 0) handle_errors();
    if (aad && aad_len > 0)
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) <= 0) handle_errors();
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) <= 0) handle_errors();
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, (void*)tag) <= 0) handle_errors();
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) { plaintext_len += len; return plaintext_len; }
    return -1;
}

/* ── Secure receive ────────────────────────────────────────────── */
// Wire format: [ length(4) | ciphertext | tag(16) ]
int secure_receive(int sock,
                   unsigned char       *data_out,
                   const unsigned char *key,
                   const unsigned char *static_iv,
                   uint64_t            *seq)
{
    uint32_t len_net;
    if (recv(sock, &len_net, 4, MSG_WAITALL) != 4) return -1;
    uint32_t cipher_len = ntohl(len_net);

    if (cipher_len == 0 || cipher_len > MAX_PAYLOAD) {
        fprintf(stderr, "[secure_receive] bad length %u\n", cipher_len);
        return -1;
    }

    unsigned char ciphertext[MAX_PAYLOAD];
    unsigned char tag[AES_TAG_LEN];

    if (recv(sock, ciphertext, cipher_len, MSG_WAITALL) != (ssize_t)cipher_len) return -1;
    if (recv(sock, tag,        AES_TAG_LEN, MSG_WAITALL) != AES_TAG_LEN)        return -1;

    unsigned char nonce[AES_IV_LEN];
    make_nonce(nonce, static_iv, *seq);

    uint64_t seq_be = htobe64(*seq);

    int plaintext_len = aes_gcm_decrypt(
        ciphertext, (int)cipher_len,
        (unsigned char*)&seq_be, sizeof(seq_be),
        tag, key, nonce, data_out);

    if (plaintext_len < 0) {
        fprintf(stderr, "[secure_receive] GCM auth FAILED (seq=%llu)\n",
                (unsigned long long)*seq);
        return -1;
    }

    (*seq)++;
    return plaintext_len;
}

/* ── Transcript hash ───────────────────────────────────────────── */
EVP_MD_CTX *transcript_ctx;

void transcript_init(void)
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

/* ── recv_all ──────────────────────────────────────────────────── */
int recv_all(int sock, unsigned char *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t r = recv(sock, buf + total, len - total, 0);
        if (r <= 0) return -1;
        total += r;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════ */
int main(void)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* ── Socket setup ── */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(EXIT_FAILURE);
    }
    if (listen(listen_fd, 1) < 0) {
        perror("listen"); exit(EXIT_FAILURE);
    }

    printf("[Server] Listening on port %d...\n", PORT);
    int sock = accept(listen_fd, NULL, NULL);
    if (sock < 0) { perror("accept"); exit(EXIT_FAILURE); }
    printf("[Server] Client connected\n");

    /* ── Handshake ── */
    transcript_init();

    /* 1. Receive ClientHello */
    handshake_hello_t ch;
    if (recv_all(sock, (unsigned char*)&ch, sizeof(ch)) < 0) {
        fprintf(stderr, "[Server] Failed to receive ClientHello\n");
        exit(EXIT_FAILURE);
    }
    transcript_update(&ch, sizeof(ch));
    printf("[Server] Received ClientHello (version=0x%04x)\n", ntohs(ch.version));

    /* 2. Send ServerHello */
    handshake_hello_t sh = { htons(0x0304), htons(0x1301) };
    send(sock, &sh, sizeof(sh), 0);
    transcript_update(&sh, sizeof(sh));
    printf("[Server] Sent ServerHello\n");

    /* 3. Load keys */
    printf("[Server] Loading keys...\n");
    EVP_PKEY *my_sign_key     = load_private_key("ed25519_key_B.pem");
    EVP_PKEY *client_sign_pub = load_public_key("ed25519_key_A_pub.pem");
    printf("[Server] Keys loaded OK\n");

    /* 4. Generate ephemeral X25519 */
    EVP_PKEY *my_x25519 = generate_x25519_key();

    /* 5. Receive client ephemeral pubkey + signature */
    unsigned char client_pub[PUBKEY_LEN];
    unsigned char client_sig[SIG_LEN];

    if (recv_all(sock, client_pub, PUBKEY_LEN) < 0) {
        fprintf(stderr, "[Server] Failed to receive client pubkey\n"); exit(EXIT_FAILURE);
    }
    transcript_update(client_pub, PUBKEY_LEN);

    if (recv_all(sock, client_sig, SIG_LEN) < 0) {
        fprintf(stderr, "[Server] Failed to receive client sig\n"); exit(EXIT_FAILURE);
    }
    transcript_update(client_sig, SIG_LEN);

    /* 6. Verify client signature over its ephemeral pubkey */
    EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new();
    if (!verify_ctx) handle_errors();
    if (EVP_DigestVerifyInit(verify_ctx, NULL, NULL, NULL, client_sign_pub) <= 0) handle_errors();
    if (EVP_DigestVerify(verify_ctx, client_sig, SIG_LEN, client_pub, PUBKEY_LEN) <= 0) {
        fprintf(stderr, "[Server] Client authentication FAILED\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(verify_ctx);
    printf("[Server] Client signature verified OK\n");

    /* 7. Send server ephemeral pubkey + signature */
    unsigned char my_pub[PUBKEY_LEN];
    size_t pub_len = PUBKEY_LEN;
    EVP_PKEY_get_raw_public_key(my_x25519, my_pub, &pub_len);

    unsigned char my_sig[SIG_LEN];
    size_t sig_len = SIG_LEN;

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) handle_errors();
    if (EVP_DigestSignInit(sign_ctx, NULL, NULL, NULL, my_sign_key) <= 0) handle_errors();
    if (EVP_DigestSign(sign_ctx, my_sig, &sig_len, my_pub, PUBKEY_LEN) <= 0) handle_errors();
    EVP_MD_CTX_free(sign_ctx);

    send(sock, my_pub, PUBKEY_LEN, 0);
    send(sock, my_sig, SIG_LEN,    0);
    transcript_update(my_pub, PUBKEY_LEN);
    transcript_update(my_sig, SIG_LEN);
    printf("[Server] Sent ephemeral key + signature\n");

    /* 8. Derive shared secret */
    EVP_PKEY *client_x25519 =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, client_pub, PUBKEY_LEN);

    unsigned char shared_secret[SHARED_SECRET_LEN];
    size_t ss_len = SHARED_SECRET_LEN;
    derive_shared_secret(my_x25519, client_x25519, shared_secret, &ss_len);

    /* 9. Transcript hash (covers everything up to this point) */
    unsigned char transcript_hash[32];
    transcript_final(transcript_hash);

    /* 10. Derive keys */
    unsigned char client_key[32],          client_iv[12];
    unsigned char server_finished_key[32], client_finished_key[32];

    hkdf_expand(shared_secret, ss_len, transcript_hash, 32, "client key",      client_key,          32);
    hkdf_expand(shared_secret, ss_len, transcript_hash, 32, "client iv",       client_iv,           12);
    hkdf_expand(shared_secret, ss_len, transcript_hash, 32, "server finished", server_finished_key, 32);
    hkdf_expand(shared_secret, ss_len, transcript_hash, 32, "client finished", client_finished_key, 32);

    /* 11. Receive client Finished and verify */
    unsigned char client_finished[32];
    if (recv_all(sock, client_finished, 32) < 0) {
        fprintf(stderr, "[Server] Failed to receive client Finished\n"); exit(EXIT_FAILURE);
    }

    unsigned char expected_cf[32];
    compute_finished(client_finished_key, transcript_hash, expected_cf);
    if (memcmp(expected_cf, client_finished, 32) != 0) {
        fprintf(stderr, "[Server] Client Finished verify FAILED\n");
        exit(EXIT_FAILURE);
    }
    printf("[Server] Client Finished verified OK\n");

    /* 12. Send server Finished */
    unsigned char server_finished[32];
    compute_finished(server_finished_key, transcript_hash, server_finished);
    send(sock, server_finished, 32, 0);

    printf("[Handshake] Complete — waiting for encrypted messages\n\n");

    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));

    /* ── Secure receive loop ── */
    uint64_t server_seq = 0;

    while (1) {
        unsigned char buffer[MAX_PAYLOAD + 1];

        int n = secure_receive(sock, buffer, client_key, client_iv, &server_seq);
        if (n <= 0) {
            printf("[Server] Client disconnected\n");
            break;
        }

        buffer[n] = '\0';
        printf("Client: %s", buffer);
        fflush(stdout);
    }

    close(sock);
    close(listen_fd);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}