/*
 * client_tap.c
 *
 * Wraps original client.c logic.
 * - Opens a TAP interface (tap_devx) to receive plain text from Device X
 * - Prints what Device X sent
 * - Encrypts it with AES-256-GCM  
 * - Sends encrypted frame to server over TCP
 *
 * Original client.c handshake + crypto kept 100% intact.
 *
 * Build:
 *   gcc client_tap.c -o client_tap -lssl -lcrypto
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>

#define SERVER_IP  "127.0.0.1"
#define PORT       1112
#define TAP_DEV    "tap_devx"
#define BUF        2048

/* ── identical to original client.c ── */
int send_all(int fd, uint8_t *buf, int len) {
    int total = 0;
    while (total < len) {
        int s = send(fd, buf+total, len-total, 0);
        if (s <= 0) return -1;
        total += s;
    }
    return total;
}

int recv_all(int fd, uint8_t *buf, int len) {
    int total = 0;
    while (total < len) {
        int r = recv(fd, buf+total, len-total, 0);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

EVP_PKEY *load_key(const char *file, int priv) {
    FILE *f = fopen(file, "r");
    if (!f) return NULL;
    EVP_PKEY *k = priv ? PEM_read_PrivateKey(f, NULL, NULL, NULL)
                       : PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

EVP_PKEY *gen_x25519(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int derive_secret(EVP_PKEY *priv, EVP_PKEY *peer, uint8_t *out) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    size_t len = 32;
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    EVP_PKEY_derive(ctx, out, &len);
    EVP_PKEY_CTX_free(ctx);
    return (int)len;
}

int derive_modern_hkdf(const unsigned char *secret, size_t secret_len,
                       const unsigned char *salt,   size_t salt_len,
                       unsigned char *out,          size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string("key",  (void *)secret, secret_len);
    *p++ = OSSL_PARAM_construct_octet_string("salt", (void *)salt,   salt_len);
    *p++ = OSSL_PARAM_construct_octet_string("info", "MySecureApp-v1", 14);
    *p   = OSSL_PARAM_construct_end();
    int ret = (EVP_KDF_derive(kctx, out, out_len, params) > 0) ? 0 : -1;
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

int encrypt_msg_with_seq(uint8_t *key, uint8_t *pt, int plen,
                         uint8_t *fixed_nonce, uint64_t seq_num,
                         uint8_t *ct, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, clen;
    unsigned char iv[12];
    memcpy(iv, fixed_nonce, 4);
    for (int i = 0; i < 8; i++)
        iv[4+i] = (seq_num >> (56 - (i*8))) & 0xFF;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, plen); clen = len;
    EVP_EncryptFinal_ex(ctx, ct+len, &len);     clen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return clen;
}

/* ── TAP: create interface, bring up, attach to bridge ── */
int tap_open(const char *dev) {
    char cmd[128];

    /* clean any leftover from previous run */
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null || true", dev);
    system(cmd);

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0)  { perror("TUNSETIFF");    close(fd); return -1; }
    if (ioctl(fd, TUNSETPERSIST, 1) < 0) { perror("TUNSETPERSIST"); close(fd); return -1; }

    snprintf(cmd, sizeof(cmd), "ip link set %s mtu 1500 up", dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set %s master br_client 2>/dev/null || true", dev);
    system(cmd);

    printf("[TAP] %s ready\n", dev);
    return fd;
}

/* ══════════════════════════════════════════════════════ */
int main(void) {

    /* ── open TAP — Device X side ── */
    int tap_fd = tap_open(TAP_DEV);
    if (tap_fd < 0) return 1;

    /* ── load keys (identical to original client.c) ── */
    EVP_PKEY *client_priv = load_key("client_priv.pem", 1);
    EVP_PKEY *server_pub  = load_key("server_pub.pem",  0);
    if (!client_priv || !server_pub) { printf("Key load failed\n"); return 1; }

    /* ── connect to server (identical to original client.c) ── */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port   = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &a.sin_addr);
    if (connect(s, (void*)&a, sizeof(a)) < 0) { perror("connect"); return 1; }

    /* ══ HANDSHAKE — identical to original client.c ══ */
    EVP_PKEY *client_eph = gen_x25519();
    unsigned char client_raw[32]; size_t l = 32;
    EVP_PKEY_get_raw_public_key(client_eph, client_raw, &l);
    send_all(s, client_raw, 32);

    unsigned char server_raw[32];
    recv_all(s, server_raw, 32);
    EVP_PKEY *server_eph = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_raw, 32);

    unsigned char transcript[64];
    memcpy(transcript,    client_raw, 32);
    memcpy(transcript+32, server_raw, 32);

    unsigned char server_sig[64];
    recv_all(s, server_sig, 64);
    EVP_MD_CTX *v = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(v, NULL, NULL, NULL, server_pub);
    if (EVP_DigestVerify(v, server_sig, 64, transcript, 64) <= 0) {
        printf("Server Auth Fail\n"); return 1;
    }
    EVP_MD_CTX_free(v);

    unsigned char client_sig[64]; size_t siglen = 64;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestSignInit(m, NULL, NULL, NULL, client_priv);
    EVP_DigestSign(m, client_sig, &siglen, transcript, 64);
    send_all(s, client_sig, 64);
    EVP_MD_CTX_free(m);

    /* ── derive session key (identical to original client.c) ── */
    unsigned char secret[32], key[32], fixed_nonce[4], key_material[36];
    derive_secret(client_eph, server_eph, secret);
    derive_modern_hkdf(secret, 32, transcript, 64, key_material, 36);
    memcpy(key,         key_material,      32);
    memcpy(fixed_nonce, key_material + 32, 4);

    printf("Secure channel established.\n");
    printf("Waiting for Device X to send a message...\n\n");

    /* ══ MAIN LOOP: read from TAP, print, encrypt, send ══ */
    uint64_t send_seq = 0;
    uint8_t  frame[BUF], ct[BUF], tag[16];

    for (;;) {
        /* read one complete Ethernet frame from tap_devx */
        int frame_len = read(tap_fd, frame, sizeof(frame));
        if (frame_len <= 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* skip frames that are not our custom EtherType 0x9999 */
        if (frame_len < 14) continue;
        uint16_t et = (frame[12] << 8) | frame[13];
        if (et != 0x9999) continue;

        /* payload = Ethernet frame minus 14-byte header */
        uint8_t *payload = frame + 14;
        int      pay_len = frame_len - 14;
        if (pay_len <= 0) continue;

        printf("[CLIENT] Received from Device X: %.*s", pay_len, (char*)payload);

        /* encrypt payload only — no Ethernet header garbage */
        int clen = encrypt_msg_with_seq(key, payload, pay_len,
                                        fixed_nonce, send_seq, ct, tag);

        /* print encrypted bytes as hex (first 16 bytes) */
        printf("[CLIENT] Encrypted (first 16 bytes): ");
        for (int i = 0; i < 16 && i < clen; i++) printf("%02x", ct[i]);
        printf("...\n");

        /* ── send: seq(8) + len(4) + ct + tag(16) ── */
        uint64_t seq = send_seq++;
        uint8_t  seq_buf[8];
        for (int i = 0; i < 8; i++)
            seq_buf[i] = (seq >> (56 - i*8)) & 0xFF;
        uint32_t net_len = htonl((uint32_t)clen);

        send_all(s, seq_buf,             8);
        send_all(s, (uint8_t*)&net_len,  4);
        send_all(s, ct,                  clen);
        send_all(s, tag,                 16);

        printf("[CLIENT] Sent encrypted frame to server (seq=%lu)\n\n",
               (unsigned long)seq);
    }

    OPENSSL_cleanse(secret,       sizeof(secret));
    OPENSSL_cleanse(key_material, sizeof(key_material));
    OPENSSL_cleanse(key,          sizeof(key));
    EVP_PKEY_free(client_priv);
    EVP_PKEY_free(server_pub);
    EVP_PKEY_free(client_eph);
    EVP_PKEY_free(server_eph);
    close(tap_fd);
    close(s);
    return 0;
}