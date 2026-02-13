#include "crypto_utils.h"
#include <arpa/inet.h>

int main() {
    if (sodium_init() < 0) return 1;
    mkdir("A", 0777); mkdir("B", 0777);
    generate_all_keys("A", "A"); // Generates A_ed_priv/pub

    unsigned char a_ed_sk[crypto_sign_SECRETKEYBYTES];
    unsigned char b_ed_pk[crypto_sign_PUBLICKEYBYTES];
    load_key("A/A_ed_priv", a_ed_sk, sizeof a_ed_sk);
    load_key("B/B_ed_pub", b_ed_pk, sizeof b_ed_pk); // Pre-shared identity

    // Ephemeral keys for HKDF session
    unsigned char ephex_pk[crypto_kx_PUBLICKEYBYTES], ephex_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(ephex_pk, ephex_sk);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in s = { .sin_family = AF_INET, .sin_port = htons(5000) };
    inet_pton(AF_INET, "127.0.0.1", &s.sin_addr);
    if (connect(sock, (struct sockaddr*)&s, sizeof(s)) < 0) { perror("Connect"); return 1; }

    // Exchange Ephemeral Public Keys
    send(sock, ephex_pk, sizeof ephex_pk, 0);
    unsigned char b_ephex_pk[crypto_kx_PUBLICKEYBYTES];
    recv(sock, b_ephex_pk, sizeof b_ephex_pk, 0);

    unsigned char rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_client_session_keys(rx, tx, ephex_pk, ephex_sk, b_ephex_pk) != 0) return 1;

    printf("[A] Handshake Complete. Secure Channel established.\n");

    while (1) {
        char msg[MSG_MAX];
        printf("A -> B: ");
        if (!fgets(msg, MSG_MAX, stdin)) break;
        msg[strcspn(msg, "\n")] = 0;

        unsigned char sig[crypto_sign_BYTES], nonce[crypto_secretbox_NONCEBYTES], ct[MSG_MAX + 128];
        crypto_sign_detached(sig, NULL, (unsigned char*)msg, strlen(msg), a_ed_sk);

        // Packet Structure: [Signature (64b)][Message]
        unsigned char payload[MSG_MAX + 64];
        memcpy(payload, sig, sizeof sig);
        memcpy(payload + sizeof sig, msg, strlen(msg));

        randombytes_buf(nonce, sizeof nonce);
        crypto_secretbox_easy(ct, payload, sizeof sig + strlen(msg), nonce, tx);
        uint16_t ct_len = (uint16_t)(sizeof sig + strlen(msg) + crypto_secretbox_MACBYTES);

        send(sock, &ct_len, sizeof ct_len, 0);
        send(sock, nonce, sizeof nonce, 0);
        send(sock, ct, ct_len, 0);
        append_transcript("A_transcript.txt", msg);

        // Receive Reply
        if (recv(sock, &ct_len, sizeof ct_len, 0) <= 0) break;
        recv(sock, nonce, sizeof nonce, 0);
        recv(sock, ct, ct_len, 0);

        unsigned char decrypted[MSG_MAX + 64];
        if (crypto_secretbox_open_easy(decrypted, ct, ct_len, nonce, rx) == 0) {
            size_t m_len = ct_len - crypto_secretbox_MACBYTES - crypto_sign_BYTES;
            unsigned char *r_sig = decrypted;
            char *r_msg = (char*)(decrypted + crypto_sign_BYTES);
            r_msg[m_len] = '\0';

            if (crypto_sign_verify_detached(r_sig, (unsigned char*)r_msg, m_len, b_ed_pk) == 0) {
                printf("B -> A: %s (Verified)\n", r_msg);
                append_transcript("A_transcript.txt", r_msg);
            }
        }
    }
    close(sock);
    return 0;
}
