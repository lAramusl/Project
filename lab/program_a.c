// program_a.c  — CLIENT
// Sends encrypted messages to the server.
// Build: gcc program_a.c -o client -lssl -lcrypto

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
#define SERVER_IP         "127.0.0.1"

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

/* ── AES-256-GCM encrypt ───────────────────────────────────────── */
int aes_gcm_encrypt(const unsigned char *plaintext,  int plaintext_len,
                    const unsigned char *aad,         int aad_len,
                    const unsigned char *key,
                    unsigned char       *iv,
                    unsigned char       *ciphertext,
                    unsigned char       *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    int len, ciphertext_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) handle_errors();
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL) <= 0) handle_errors();
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) <= 0) handle_errors();
    if (aad && aad_len > 0)
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) <= 0) handle_errors();
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) <= 0) handle_errors();
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0) handle_errors();
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag) <= 0) handle_errors();

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/* ── Secure send ───────────────────────────────────────────────── */
// Wire format: [ length(4) | ciphertext | tag(16) ]
void secure_send(int sock,
                 const unsigned char *data,   size_t len,
                 const unsigned char *key,
                 const unsigned char *static_iv,
                 uint64_t            *seq)
{
    if (len > MAX_PAYLOAD) {
        fprintf(stderr, "[secure_send] payload too large\n");
        exit(EXIT_FAILURE);
    }

    unsigned char nonce[AES_IV_LEN];
    make_nonce(nonce, static_iv, *seq);

    uint64_t seq_be = htobe64(*seq);

    unsigned char ciphertext[MAX_PAYLOAD];
    unsigned char tag[AES_TAG_LEN];

    int cipher_len = aes_gcm_encrypt(
        data, (int)len,
        (unsigned char*)&seq_be, sizeof(seq_be),
        key, nonce, ciphertext, tag);

    if (cipher_len < 0) {
        fprintf(stderr, "[secure_send] encryption failed\n");
        exit(EXIT_FAILURE);
    }

    uint32_t len_net = htonl((uint32_t)cipher_len);
    if (send(sock, &len_net,   4,           0) != 4)           goto send_err;
    if (send(sock, ciphertext, cipher_len,  0) != cipher_len)  goto send_err;
    if (send(sock, tag,        AES_TAG_LEN, 0) != AES_TAG_LEN) goto send_err;

    (*seq)++;
    return;

send_err:
    fprintf(stderr, "[secure_send] send() failed\n");
    exit(EXIT_FAILURE);
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

    /* ── Connect ── */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); exit(EXIT_FAILURE);
    }
    printf("[Client] Connected to server\n");

    /* ── Handshake ── */
    transcript_init();

    /* 1. Send ClientHello */
    handshake_hello_t ch = { htons(0x0304), htons(0x1301) };
    send(sock, &ch, sizeof(ch), 0);
    transcript_update(&ch, sizeof(ch));
    printf("[Client] Sent ClientHello\n");

    /* 2. Receive ServerHello */
    handshake_hello_t sh;
    if (recv_all(sock, (unsigned char*)&sh, sizeof(sh)) < 0) {
        fprintf(stderr, "[Client] Failed to receive ServerHello\n"); exit(EXIT_FAILURE);
    }
    transcript_update(&sh, sizeof(sh));
    printf("[Client] Received ServerHello (version=0x%04x)\n", ntohs(sh.version));

    /* 3. Load keys */
    printf("[Client] Loading keys...\n");
    EVP_PKEY *my_sign_key     = load_private_key("ed25519_key_A.pem");
    EVP_PKEY *server_sign_pub = load_public_key("ed25519_key_B_pub.pem");
    printf("[Client] Keys loaded OK\n");

    /* 4. Generate ephemeral X25519 */
    EVP_PKEY *my_x25519 = generate_x25519_key();

    unsigned char my_pub[PUBKEY_LEN];
    size_t pub_len = PUBKEY_LEN;
    EVP_PKEY_get_raw_public_key(my_x25519, my_pub, &pub_len);

    /* 5. Sign our ephemeral pubkey with our long-term Ed25519 key */
    unsigned char my_sig[SIG_LEN];
    size_t sig_len = SIG_LEN;

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) handle_errors();
    if (EVP_DigestSignInit(sign_ctx, NULL, NULL, NULL, my_sign_key) <= 0) handle_errors();
    if (EVP_DigestSign(sign_ctx, my_sig, &sig_len, my_pub, PUBKEY_LEN) <= 0) handle_errors();
    EVP_MD_CTX_free(sign_ctx);

    /* 6. Send client ephemeral pubkey + signature */
    send(sock, my_pub, PUBKEY_LEN, 0);
    send(sock, my_sig, SIG_LEN,    0);
    transcript_update(my_pub, PUBKEY_LEN);
    transcript_update(my_sig, SIG_LEN);
    printf("[Client] Sent ephemeral key + signature\n");

    /* 7. Receive server ephemeral pubkey + signature */
    unsigned char server_pub[PUBKEY_LEN];
    unsigned char server_sig[SIG_LEN];

    if (recv_all(sock, server_pub, PUBKEY_LEN) < 0) {
        fprintf(stderr, "[Client] Failed to receive server pubkey\n"); exit(EXIT_FAILURE);
    }
    if (recv_all(sock, server_sig, SIG_LEN) < 0) {
        fprintf(stderr, "[Client] Failed to receive server sig\n"); exit(EXIT_FAILURE);
    }

    /* 8. Verify server signature */
    EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new();
    if (!verify_ctx) handle_errors();
    if (EVP_DigestVerifyInit(verify_ctx, NULL, NULL, NULL, server_sign_pub) <= 0) handle_errors();
    if (EVP_DigestVerify(verify_ctx, server_sig, SIG_LEN, server_pub, PUBKEY_LEN) <= 0) {
        fprintf(stderr, "[Client] Server authentication FAILED\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(verify_ctx);
    printf("[Client] Server signature verified OK\n");

    transcript_update(server_pub, PUBKEY_LEN);
    transcript_update(server_sig, SIG_LEN);

    /* 9. Derive shared secret */
    EVP_PKEY *server_x25519 =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pub, PUBKEY_LEN);

    unsigned char shared_secret[SHARED_SECRET_LEN];
    size_t ss_len = SHARED_SECRET_LEN;
    derive_shared_secret(my_x25519, server_x25519, shared_secret, &ss_len);

    /* 10. Transcript hash */
    unsigned char transcript_hash[32];
    transcript_final(transcript_hash);

    /* 11. Derive client keys */
    unsigned char client_key[32],          client_iv[12];
    unsigned char client_finished_key[32], server_finished_key[32];

    hkdf_expand(shared_secret, ss_len, transcript_hash, 32, "client key",      client_key,          32);
    hkdf_expand(shared_secret, ss_len, transcript_hash, 32, "client iv",       client_iv,           12);
    hkdf_expand(shared_secret, ss_len, transcript_hash, 32, "client finished", client_finished_key, 32);
    hkdf_expand(shared_secret, ss_len, transcript_hash, 32, "server finished", server_finished_key, 32);

    /* 12. Send client Finished */
    unsigned char client_finished[32];
    compute_finished(client_finished_key, transcript_hash, client_finished);
    send(sock, client_finished, 32, 0);
    printf("[Client] Sent Finished\n");

    /* 13. Receive + verify server Finished */
    unsigned char server_finished[32];
    if (recv_all(sock, server_finished, 32) < 0) {
        fprintf(stderr, "[Client] Failed to receive server Finished\n"); exit(EXIT_FAILURE);
    }

    unsigned char expected_sf[32];
    compute_finished(server_finished_key, transcript_hash, expected_sf);
    if (memcmp(expected_sf, server_finished, 32) != 0) {
        fprintf(stderr, "[Client] Server Finished verify FAILED\n");
        exit(EXIT_FAILURE);
    }

    printf("[Handshake] Complete — type messages below (Ctrl+D to quit)\n\n");

    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));

    /* ── Secure send loop ── */
    uint64_t client_seq = 0;
    char line[MAX_PAYLOAD];

    while (1) {
        printf("You: ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin))
            break;

        secure_send(sock,
                    (unsigned char*)line, strlen(line),
                    client_key, client_iv,
                    &client_seq);
    }

    printf("[Client] Disconnecting\n");
    close(sock);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}