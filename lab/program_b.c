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


EVP_PKEY* load_public_key(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey)
        handle_errors();

    return pkey;
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
                     const unsigned char *ecdh_pub,
                     size_t ecdh_pub_len)
{
    unsigned char signature[SIG_LEN];
    size_t sig_len = SIG_LEN;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sign_key) <= 0)
        handle_errors();

    if (EVP_DigestSign(mdctx,
                       signature,
                       &sig_len,
                       ecdh_pub,
                       ecdh_pub_len) <= 0)
        handle_errors();

    EVP_MD_CTX_free(mdctx);

    send(sock, ecdh_pub, ecdh_pub_len, 0);
    send(sock, signature, SIG_LEN, 0);
}

void recv_and_verify_key(int sock,
                         EVP_PKEY *peer_sign_pubkey,
                         unsigned char *peer_ecdh_pub)
{
    unsigned char peer_sig[SIG_LEN];

    recv(sock, peer_ecdh_pub, PUBKEY_LEN, MSG_WAITALL);
    recv(sock, peer_sig, SIG_LEN, MSG_WAITALL);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, peer_sign_pubkey) <= 0)
        handle_errors();

    if (EVP_DigestVerify(mdctx,
                         peer_sig,
                         SIG_LEN,
                         peer_ecdh_pub,
                         PUBKEY_LEN) <= 0) {
        fprintf(stderr, "Signature verification failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
}



int main(void)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_PKEY *my_sign_key = load_private_key("ed25519_key.pem");
    EVP_PKEY *peer_sign_pubkey = load_public_key("peer_ed25519_pub.pem");

    if (!my_sign_key || !peer_sign_pubkey) {
        fprintf(stderr, "Signing keys missing\n");
        exit(EXIT_FAILURE);
    }

    // 1. Load private key (X25519 expected)
    EVP_PKEY *privkey = load_private_key("x25519_key.pem");

    if (!privkey) {
        printf("Generating new X25519 key...\n");
        privkey = generate_x25519_key();
        write_private_key("x25519_key.pem", privkey);
    }


    // 2. Extract public key
    unsigned char public_key[PUBKEY_LEN];
    size_t public_key_len = PUBKEY_LEN;
    extract_public_key(privkey, public_key, &public_key_len);

    // 3. Create socket (client mode)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    // 4. send our key + signature
    send_signed_key(sock,
                    my_sign_key,
                    public_key,
                    public_key_len);

    // 5. receive peer key + verify
    unsigned char peer_pubkey[PUBKEY_LEN];

    recv_and_verify_key(sock,
                        peer_sign_pubkey,
                        peer_pubkey);

    EVP_PKEY *peerkey =
    EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,
                                NULL,
                                peer_pubkey,
                                PUBKEY_LEN);

    // 6. Derive shared secret
    unsigned char shared_secret[SHARED_SECRET_LEN];
    size_t shared_secret_len = SHARED_SECRET_LEN;

    derive_shared_secret(privkey, peerkey,
                         shared_secret, &shared_secret_len);

    unsigned char aes_key[AES_KEY_LEN];
    derive_aes_key(shared_secret, shared_secret_len, aes_key);

    printf("Shared secret (%zu bytes):\n", shared_secret_len);
    for (size_t i = 0; i < shared_secret_len; i++)
        printf("%02x", shared_secret[i]);
    printf("\n");

    uint32_t send_seq = 0;
    uint32_t recv_seq = 0;
    
    transcript_t transcript;
    transcript_init(&transcript);

    // --- Handshake transcript update (ECDH keys) ---
    transcript_update(&transcript, public_key, PUBKEY_LEN);
    transcript_update(&transcript, peer_pubkey, PUBKEY_LEN);

    // --- Compute handshake hash ---
    unsigned char handshake_hash[TRANSCRIPT_HASH_LEN];
    transcript_final(&transcript, handshake_hash);

    // --- Finished message (send hash securely) ---
    send_secure_message(sock,
                        &send_seq,
                        NULL,              // transcript not used post-handshake
                        handshake_hash,
                        TRANSCRIPT_HASH_LEN,
                        aes_key);

    // --- Receive peer Finished ---
    unsigned char peer_finished[TRANSCRIPT_HASH_LEN];

    int finished_len = recv_secure_message(sock,
                                        &recv_seq,
                                        NULL,
                                        peer_finished,
                                        aes_key);

    if (finished_len != TRANSCRIPT_HASH_LEN ||
        memcmp(handshake_hash, peer_finished, TRANSCRIPT_HASH_LEN) != 0) {
        fprintf(stderr, "Finished verification failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Handshake fully verified\n");

    // =====================
    // SECURE CHAT LOOP
    // =====================

    while (1)
    {
        char input[MAX_PAYLOAD];
        unsigned char decrypted[MAX_PAYLOAD];

        printf("You: ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        int input_len = strlen(input);

        int received_len = recv_secure_message(sock,
                                            &recv_seq,
                                            NULL,
                                            decrypted,
                                            aes_key);

        if (received_len <= 0) {
            printf("Connection closed or error\n");
            break;
        }

        decrypted[received_len] = '\0';
        printf("Peer: %s", decrypted);

        send_secure_message(sock,
                            &send_seq,
                            NULL,
                            (unsigned char*)input,
                            input_len,
                            aes_key);
    }

    EVP_PKEY_free(my_sign_key);
    EVP_PKEY_free(peer_sign_pubkey);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(privkey);

    close(sock);

    EVP_cleanup();
    ERR_free_strings();

    return 0;

}
