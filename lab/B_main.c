#include "crypto_utils.h"
#include <arpa/inet.h>

int main() {
    if (sodium_init() < 0) return 1;
    mkdir("B", 0777); 
    generate_all_keys("B", "B");

    unsigned char b_ed_sk[crypto_sign_SECRETKEYBYTES];
    unsigned char a_ed_pk[crypto_sign_PUBLICKEYBYTES];
    load_key("B/B_ed_priv", b_ed_sk, sizeof b_ed_sk);
    load_key("A/A_ed_pub", a_ed_pk, sizeof a_ed_pk);

    unsigned char ephex_pk[crypto_kx_PUBLICKEYBYTES], ephex_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(ephex_pk, ephex_sk);

    int serv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(5000), .sin_addr.s_addr = INADDR_ANY };
    int opt = 1; setsockopt(serv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(serv, (struct sockaddr*)&addr, sizeof(addr));
    listen(serv, 1);

    printf("[B] Listening on port 5000...\n");
    int sock = accept(serv, NULL, NULL);

    unsigned char a_ephex_pk[crypto_kx_PUBLICKEYBYTES];
    recv(sock, a_ephex_pk, sizeof a_ephex_pk, 0);
    send(sock, ephex_pk, sizeof ephex_pk, 0);

    unsigned char rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_server_session_keys(rx, tx, ephex_pk, ephex_sk, a_ephex_pk) != 0) return 1;

    while (1) {
        uint16_t ct_len;
        unsigned char nonce[crypto_secretbox_NONCEBYTES], ct[MSG_MAX + 128];
        if (recv(sock, &ct_len, sizeof ct_len, 0) <= 0) break;
        recv(sock, nonce, sizeof nonce, 0);
        recv(sock, ct, ct_len, 0);

        unsigned char decrypted[MSG_MAX + 64];
        if (crypto_secretbox_open_easy(decrypted, ct, ct_len, nonce, rx) == 0) {
            size_t m_len = ct_len - crypto_secretbox_MACBYTES - crypto_sign_BYTES;
            unsigned char *r_sig = decrypted;
            char *r_msg = (char*)(decrypted + crypto_sign_BYTES);
            r_msg[m_len] = '\0';

            if (crypto_sign_verify_detached(r_sig, (unsigned char*)r_msg, m_len, a_ed_pk) == 0) {
                printf("A -> B: %s (Verified)\n", r_msg);
                append_transcript("B_transcript.txt", r_msg);
            }
        }

        printf("B -> A: ");
        char reply[MSG_MAX];
        if (!fgets(reply, MSG_MAX, stdin)) break;
        reply[strcspn(reply, "\n")] = 0;

        unsigned char sig[crypto_sign_BYTES];
        crypto_sign_detached(sig, NULL, (unsigned char*)reply, strlen(reply), b_ed_sk);

        unsigned char payload[MSG_MAX + 64];
        memcpy(payload, sig, sizeof sig);
        memcpy(payload + sizeof sig, reply, strlen(reply));

        randombytes_buf(nonce, sizeof nonce);
        crypto_secretbox_easy(ct, payload, sizeof sig + strlen(reply), nonce, tx);
        uint16_t out_len = (uint16_t)(sizeof sig + strlen(reply) + crypto_secretbox_MACBYTES);

        send(sock, &out_len, sizeof out_len, 0);
        send(sock, nonce, sizeof nonce, 0);
        send(sock, ct, out_len, 0);
        append_transcript("B_transcript.txt", reply);
    }
    close(sock); close(serv);
    return 0;
}
