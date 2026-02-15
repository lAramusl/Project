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

void extract_public_key(EVP_PKEY *pkey, unsigned char *pubkey, size_t *len)
{
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey, len) <= 0)
        handle_errors();
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

// ===== AUTHENTICATION FUNCTION (Ed25519) =====

void authenticate_peer(int sock,
                       EVP_PKEY *my_sign_key,
                       EVP_PKEY *peer_sign_pubkey,
                       const unsigned char *my_ecdh_pub,
                       size_t my_ecdh_pub_len,
                       const unsigned char *peer_ecdh_pub,
                       size_t peer_ecdh_pub_len)
{
    unsigned char signature[SIG_LEN];
    size_t sig_len = SIG_LEN;

    // ---- 1. SIGN peer's ECDH public key ----
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, my_sign_key) <= 0)
        handle_errors();

    if (EVP_DigestSign(mdctx,
                       signature,
                       &sig_len,
                       peer_ecdh_pub,
                       peer_ecdh_pub_len) <= 0)
        handle_errors();

    EVP_MD_CTX_free(mdctx);

    // ---- 2. SEND SIGNATURE ----
    if (send(sock, signature, sig_len, 0) != sig_len) {
        perror("send signature");
        exit(EXIT_FAILURE);
    }

    // ---- 3. RECEIVE PEER SIGNATURE ----
    unsigned char peer_sig[SIG_LEN];
    ssize_t received = recv(sock, peer_sig, SIG_LEN, MSG_WAITALL);
    if (received != SIG_LEN) {
        perror("recv signature");
        exit(EXIT_FAILURE);
    }

    // ---- 4. VERIFY PEER SIGNATURE ----
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, peer_sign_pubkey) <= 0)
        handle_errors();

    if (EVP_DigestVerify(mdctx,
                         peer_sig,
                         SIG_LEN,
                         my_ecdh_pub,
                         my_ecdh_pub_len) <= 0) {
        fprintf(stderr, "Authentication failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);

    printf("Authentication successful\n");
}

EVP_PKEY* extract_ed25519_public(EVP_PKEY *privkey)
{
    unsigned char pub[ED25519_PUBKEY_LEN];
    size_t len = ED25519_PUBKEY_LEN;

    if (EVP_PKEY_get_raw_public_key(privkey, pub, &len) <= 0)
        handle_errors();

    EVP_PKEY *pubkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
                                    NULL,
                                    pub,
                                    len);

    if (!pubkey)
        handle_errors();

    return pubkey;
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

typedef struct {
    EVP_MD_CTX *ctx;
} transcript_t;

void transcript_init(transcript_t *t)
{
    t->ctx = EVP_MD_CTX_new();
    if (!t->ctx) handle_errors();

    if (EVP_DigestInit_ex(t->ctx, EVP_sha256(), NULL) <= 0)
        handle_errors();
}

void transcript_update(transcript_t *t,
                       const unsigned char *data,
                       size_t len)
{
    if (EVP_DigestUpdate(t->ctx, data, len) <= 0)
        handle_errors();
}

void transcript_final(transcript_t *t,
                      unsigned char *out_hash)
{
    unsigned int len = 0;

    if (EVP_DigestFinal_ex(t->ctx, out_hash, &len) <= 0)
        handle_errors();

    EVP_MD_CTX_free(t->ctx);
}

// ================= SECURE SEND WITH SEQ + TRANSCRIPT =================

int send_secure_message(int sock,
                        uint32_t *send_seq,
                        transcript_t *transcript,
                        const unsigned char *plaintext,
                        int plaintext_len,
                        const unsigned char *aes_key)
{
    unsigned char iv[AES_IV_LEN];
    unsigned char ciphertext[MAX_PAYLOAD];
    unsigned char tag[AES_TAG_LEN];

    RAND_bytes(iv, AES_IV_LEN);

    uint32_t seq_net = htonl(*send_seq);

    int ciphertext_len = aes_gcm_encrypt(
        plaintext,
        plaintext_len,
        (unsigned char*)&seq_net,
        sizeof(seq_net),
        aes_key,
        iv,
        ciphertext,
        tag
    );

    if (ciphertext_len < 0)
        return -1;

    uint32_t len_net = htonl(ciphertext_len);

    // ---- SEND ORDER ----
    send(sock, &seq_net, 4, 0);
    send(sock, &len_net, 4, 0);
    send(sock, iv, AES_IV_LEN, 0);
    send(sock, ciphertext, ciphertext_len, 0);
    send(sock, tag, AES_TAG_LEN, 0);

    // ---- TRANSCRIPT UPDATE ----
    if (transcript)
    {
        transcript_update(transcript, (unsigned char*)&seq_net, 4);
        transcript_update(transcript, (unsigned char*)&len_net, 4);
        transcript_update(transcript, iv, AES_IV_LEN);
        transcript_update(transcript, ciphertext, ciphertext_len);
        transcript_update(transcript, tag, AES_TAG_LEN);
    }

    (*send_seq)++;

    return 0;
}

// ================= SECURE RECEIVE =================

int recv_secure_message(int sock,
                        uint32_t *recv_seq,
                        transcript_t *transcript,
                        unsigned char *plaintext_out,
                        const unsigned char *aes_key)
{
    uint32_t seq_net, len_net;

    if (recv(sock, &seq_net, 4, MSG_WAITALL) != 4)
        return -1;

    if (recv(sock, &len_net, 4, MSG_WAITALL) != 4)
        return -1;

    uint32_t seq = ntohl(seq_net);
    uint32_t ciphertext_len = ntohl(len_net);

    if (ciphertext_len > MAX_PAYLOAD)
        return -1;

    // ---- SEQUENCE CHECK ----
    if (seq != *recv_seq)
        return -1;

    unsigned char iv[AES_IV_LEN];
    unsigned char ciphertext[MAX_PAYLOAD];
    unsigned char tag[AES_TAG_LEN];

    if (recv(sock, iv, AES_IV_LEN, MSG_WAITALL) != AES_IV_LEN)
        return -1;

    if (recv(sock, ciphertext, ciphertext_len, MSG_WAITALL) != ciphertext_len)
        return -1;

    if (recv(sock, tag, AES_TAG_LEN, MSG_WAITALL) != AES_TAG_LEN)
        return -1;

    int plaintext_len = aes_gcm_decrypt(
        ciphertext,
        ciphertext_len,
        (unsigned char*)&seq_net,
        sizeof(seq_net),
        tag,
        aes_key,
        iv,
        plaintext_out
    );

    if (plaintext_len < 0)
        return -1;

    // ---- TRANSCRIPT UPDATE ----
    if(transcript)
    {
        transcript_update(transcript, (unsigned char*)&seq_net, 4);
        transcript_update(transcript, (unsigned char*)&len_net, 4);
        transcript_update(transcript, iv, AES_IV_LEN);
        transcript_update(transcript, ciphertext, ciphertext_len);
        transcript_update(transcript, tag, AES_TAG_LEN);
    }

    (*recv_seq)++;

    return plaintext_len;
}

void send_signed_key(int sock,
                     EVP_PKEY *sign_key,
                     EVP_PKEY *sign_pubkey,
                     const unsigned char *ecdh_pub,
                     size_t ecdh_pub_len,
                     unsigned char *signature_out)
{
    unsigned char sign_pub[ED25519_PUBKEY_LEN];
    size_t sign_pub_len = ED25519_PUBKEY_LEN;

    if (EVP_PKEY_get_raw_public_key(sign_pubkey,
                                    sign_pub,
                                    &sign_pub_len) <= 0)
        handle_errors();

    size_t sig_len = SIG_LEN;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sign_key);

    EVP_DigestSign(mdctx,
                   signature_out,
                   &sig_len,
                   ecdh_pub,
                   ecdh_pub_len);

    EVP_MD_CTX_free(mdctx);

    send(sock, ecdh_pub, ecdh_pub_len, 0);
    send(sock, sign_pub, ED25519_PUBKEY_LEN, 0);
    send(sock, signature_out, SIG_LEN, 0);
}

void recv_and_verify_key(int sock,
                         unsigned char *peer_ecdh_pub,
                         unsigned char *peer_sign_pub,
                         unsigned char *peer_sig_out)
{
    recv(sock, peer_ecdh_pub, PUBKEY_LEN, MSG_WAITALL);
    recv(sock, peer_sign_pub, ED25519_PUBKEY_LEN, MSG_WAITALL);
    recv(sock, peer_sig_out, SIG_LEN, MSG_WAITALL);

    EVP_PKEY *peer_sign_pubkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
                                    NULL,
                                    peer_sign_pub,
                                    ED25519_PUBKEY_LEN);

    if (!peer_sign_pubkey)
        handle_errors();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, peer_sign_pubkey);

    if (EVP_DigestVerify(mdctx,
                         peer_sig_out,
                         SIG_LEN,
                         peer_ecdh_pub,
                         PUBKEY_LEN) <= 0) {
        fprintf(stderr, "Signature verification failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(peer_sign_pubkey);
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

    // --- Load ONLY private signing key ---
    EVP_PKEY *my_sign_key = load_private_key("ed25519_key_A.pem");
    if (!my_sign_key) {
        fprintf(stderr, "Signing key missing\n");
        exit(EXIT_FAILURE);
    }

    // --- Extract own Ed25519 public key ---
    EVP_PKEY *my_sign_pubkey = extract_ed25519_public(my_sign_key);

    // --- Generate ephemeral X25519 ---
    EVP_PKEY *my_x25519 = generate_x25519_key();

    unsigned char my_pub[PUBKEY_LEN];
    size_t my_pub_len = PUBKEY_LEN;
    extract_public_key(my_x25519, my_pub, &my_pub_len);

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

    // =============================
    // HANDSHAKE
    // =============================

    transcript_t transcript;
    transcript_init(&transcript);

    unsigned char my_sig[SIG_LEN];
    unsigned char peer_pub[PUBKEY_LEN];
    unsigned char peer_sign_pub[ED25519_PUBKEY_LEN];
    unsigned char peer_sig[SIG_LEN];

    // --- A sends first ---
    send_signed_key(sock,
                    my_sign_key,
                    my_sign_pubkey,
                    my_pub,
                    PUBKEY_LEN,
                    my_sig);

    unsigned char my_sign_pub_raw[ED25519_PUBKEY_LEN];
    size_t tmp_len = ED25519_PUBKEY_LEN;
    EVP_PKEY_get_raw_public_key(my_sign_pubkey,
                                my_sign_pub_raw,
                                &tmp_len);

    transcript_update(&transcript, my_pub, PUBKEY_LEN);
    transcript_update(&transcript, my_sign_pub_raw, ED25519_PUBKEY_LEN);
    transcript_update(&transcript, my_sig, SIG_LEN);

    // --- A receives ---
    recv_and_verify_key(sock,
                        peer_pub,
                        peer_sign_pub,
                        peer_sig);

    transcript_update(&transcript, peer_pub, PUBKEY_LEN);
    transcript_update(&transcript, peer_sign_pub, ED25519_PUBKEY_LEN);
    transcript_update(&transcript, peer_sig, SIG_LEN);

    // --- Build peer X25519 ---
    EVP_PKEY *peer_x25519 =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,
                                    NULL,
                                    peer_pub,
                                    PUBKEY_LEN);

    // --- Derive shared secret ---
    unsigned char shared_secret[SHARED_SECRET_LEN];
    size_t ss_len = SHARED_SECRET_LEN;

    derive_shared_secret(my_x25519,
                         peer_x25519,
                         shared_secret,
                         &ss_len);

    unsigned char aes_key[AES_KEY_LEN];
    derive_aes_key(shared_secret, ss_len, aes_key);

    // --- Transcript hash ---
    unsigned char handshake_hash[TRANSCRIPT_HASH_LEN];
    transcript_final(&transcript, handshake_hash);

    uint32_t send_seq = 0;
    uint32_t recv_seq = 0;

    // --- A sends Finished first ---
    send_secure_message(sock,
                        &send_seq,
                        NULL,
                        handshake_hash,
                        TRANSCRIPT_HASH_LEN,
                        aes_key);

    // --- A receives Finished ---
    unsigned char peer_finished[TRANSCRIPT_HASH_LEN];

    int flen = recv_secure_message(sock,
                                   &recv_seq,
                                   NULL,
                                   peer_finished,
                                   aes_key);

    if (flen != TRANSCRIPT_HASH_LEN ||
        memcmp(handshake_hash,
               peer_finished,
               TRANSCRIPT_HASH_LEN) != 0) {
        fprintf(stderr, "Finished verification failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Handshake verified\n");

    // =============================
    // SECURE CHAT
    // =============================

    while (1)
    {
        char input[MAX_PAYLOAD];
        unsigned char decrypted[MAX_PAYLOAD];

        printf("You: ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        int len = strlen(input);

        send_secure_message(sock,
                            &send_seq,
                            NULL,
                            (unsigned char*)input,
                            len,
                            aes_key);

        int rlen = recv_secure_message(sock,
                                       &recv_seq,
                                       NULL,
                                       decrypted,
                                       aes_key);

        if (rlen <= 0)
            break;

        decrypted[rlen] = 0;
        printf("Peer: %s", decrypted);
    }

    EVP_PKEY_free(my_sign_key);
    EVP_PKEY_free(my_sign_pubkey);
    EVP_PKEY_free(my_x25519);
    EVP_PKEY_free(peer_x25519);

    close(sock);

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}


