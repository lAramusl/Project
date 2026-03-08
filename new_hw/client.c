/*
 * tap_client.c  —  bidirectional L2 tunnel, client side
 *
 * Device X  <──tap_devx──>  [tap_client]  <──TCP/AES──>  [tap_server]  <──tap_devy──>  Device Y
 *
 * Two threads:
 *   tx_thread: TAP read  → encrypt → send to server
 *   rx_thread: recv from server → decrypt → TAP write  (replies back to Device X)
 *
 * Build:
 *   gcc tap_client.c -o client_tap -lssl -lcrypto -lpthread
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

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
#define MTU        1500
#define BUF        (MTU + 64)

/* ── shared state between threads ── */
typedef struct {
    int      sock;
    int      tap_fd;
    uint8_t  key[32];
    uint8_t  fixed_nonce[4];
    uint64_t send_seq;   /* protected by send_mutex */
    uint64_t recv_seq;
    pthread_mutex_t send_mutex;
} tunnel_t;

/* ── utility ── */
static int send_all(int fd, const uint8_t *buf, int len) {
    int t = 0;
    while (t < len) { int s = send(fd,buf+t,len-t,0); if(s<=0)return -1; t+=s; }
    return t;
}
static int recv_all(int fd, uint8_t *buf, int len) {
    int t = 0;
    while (t < len) { int r = recv(fd,buf+t,len-t,0); if(r<=0)return -1; t+=r; }
    return t;
}

/* ── TAP create ── */
static int tap_open(const char *dev) {
    char cmd[128];
    snprintf(cmd,sizeof(cmd),"ip link del %s 2>/dev/null || true",dev);
    system(cmd);

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0)     { perror("TUNSETIFF");  close(fd); return -1; }
    if (ioctl(fd, TUNSETPERSIST, 1) < 0)    { perror("TUNSETPERSIST"); close(fd); return -1; }

    snprintf(cmd,sizeof(cmd),"ip link set %s mtu 1500 up",dev); system(cmd);
    snprintf(cmd,sizeof(cmd),"ip link set %s master br_client 2>/dev/null||true",dev); system(cmd);

    printf("[TAP] %s  up and bridged to br_client\n", dev);
    return fd;
}

/* ── key load ── */
static EVP_PKEY *load_key(const char *f, int priv) {
    FILE *fp = fopen(f,"r"); if(!fp)return NULL;
    EVP_PKEY *k = priv ? PEM_read_PrivateKey(fp,NULL,NULL,NULL)
                       : PEM_read_PUBKEY(fp,NULL,NULL,NULL);
    fclose(fp); return k;
}
static EVP_PKEY *gen_x25519(void) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
    EVP_PKEY *k = NULL;
    EVP_PKEY_keygen_init(c); EVP_PKEY_keygen(c,&k); EVP_PKEY_CTX_free(c);
    return k;
}
static void derive_secret(EVP_PKEY *priv, EVP_PKEY *peer, uint8_t *out) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(priv,NULL); size_t l=32;
    EVP_PKEY_derive_init(c); EVP_PKEY_derive_set_peer(c,peer); EVP_PKEY_derive(c,out,&l);
    EVP_PKEY_CTX_free(c);
}
static void derive_hkdf(const uint8_t *sec,size_t sl,const uint8_t *salt,size_t tl,uint8_t *out,size_t ol){
    EVP_KDF *kdf=EVP_KDF_fetch(NULL,"HKDF",NULL);
    EVP_KDF_CTX *kc=EVP_KDF_CTX_new(kdf);
    OSSL_PARAM p[5],*pp=p;
    *pp++=OSSL_PARAM_construct_utf8_string("digest","SHA256",0);
    *pp++=OSSL_PARAM_construct_octet_string("key",(void*)sec,sl);
    *pp++=OSSL_PARAM_construct_octet_string("salt",(void*)salt,tl);
    *pp++=OSSL_PARAM_construct_octet_string("info","MySecureApp-v1",14);
    *pp  =OSSL_PARAM_construct_end();
    EVP_KDF_derive(kc,out,ol,p);
    EVP_KDF_CTX_free(kc); EVP_KDF_free(kdf);
}

/* ── crypto ── */
static int encrypt_frame(uint8_t *key,uint8_t *pt,int plen,
                         uint8_t *fn,uint64_t seq,uint8_t *ct,uint8_t *tag){
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int len,clen;
    uint8_t iv[12]; memcpy(iv,fn,4);
    for(int i=0;i<8;i++) iv[4+i]=(seq>>(56-i*8))&0xFF;
    EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),NULL,key,iv);
    EVP_EncryptUpdate(c,ct,&len,pt,plen); clen=len;
    EVP_EncryptFinal_ex(c,ct+len,&len); clen+=len;
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag);
    EVP_CIPHER_CTX_free(c); return clen;
}
static int decrypt_frame(uint8_t *key,uint8_t *ct,int clen,
                         uint8_t *fn,uint64_t seq,uint8_t *tag,uint8_t *pt){
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int len,plen;
    uint8_t iv[12]; memcpy(iv,fn,4);
    for(int i=0;i<8;i++) iv[4+i]=(seq>>(56-i*8))&0xFF;
    EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),NULL,key,iv);
    EVP_DecryptUpdate(c,pt,&len,ct,clen); plen=len;
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,tag);
    int r=EVP_DecryptFinal_ex(c,pt+len,&len);
    EVP_CIPHER_CTX_free(c); return (r>0)?(plen+len):-1;
}

/* ── TX thread: TAP → encrypt → server ── */
static void *tx_thread(void *arg) {
    tunnel_t *t = (tunnel_t*)arg;
    uint8_t frame[BUF], ct[BUF], tag[16];
    for(;;) {
        int flen = read(t->tap_fd, frame, sizeof(frame));
        if(flen <= 0) { if(errno==EINTR)continue; break; }

        pthread_mutex_lock(&t->send_mutex);
        uint64_t seq = t->send_seq++;
        pthread_mutex_unlock(&t->send_mutex);

        int clen = encrypt_frame(t->key, frame, flen, t->fixed_nonce, seq, ct, tag);

        uint8_t seq_buf[8];
        for(int i=0;i<8;i++) seq_buf[i]=(seq>>(56-i*8))&0xFF;
        uint32_t net_len = htonl((uint32_t)clen);

        pthread_mutex_lock(&t->send_mutex);
        send_all(t->sock, seq_buf,             8);
        send_all(t->sock, (uint8_t*)&net_len,  4);
        send_all(t->sock, ct,                  clen);
        send_all(t->sock, tag,                 16);
        pthread_mutex_unlock(&t->send_mutex);

        printf("[TX] seq=%-4lu  %d bytes → server\n",(unsigned long)seq,flen);
    }
    return NULL;
}

/* ── RX thread: server → decrypt → TAP ── */
static void *rx_thread(void *arg) {
    tunnel_t *t = (tunnel_t*)arg;
    uint8_t seq_buf[8], ct[BUF], tag[16], pt[BUF];
    for(;;) {
        if(recv_all(t->sock, seq_buf, 8) <= 0) break;
        uint64_t rseq=0;
        for(int i=0;i<8;i++) rseq=(rseq<<8)|seq_buf[i];

        uint32_t net_len;
        if(recv_all(t->sock,(uint8_t*)&net_len,4)<=0) break;
        int clen=(int)ntohl(net_len);
        if(clen<=0||clen>BUF) break;

        if(recv_all(t->sock,ct,clen)<=0) break;
        if(recv_all(t->sock,tag,16)<=0) break;

        int plen=decrypt_frame(t->key,ct,clen,t->fixed_nonce,rseq,tag,pt);
        if(plen<0){ fprintf(stderr,"[RX] integrity fail seq=%lu\n",(unsigned long)rseq); continue; }

        write(t->tap_fd, pt, plen);
        printf("[RX] seq=%-4lu  %d bytes → Device X\n",(unsigned long)rseq,plen);
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════ */
int main(void) {
    EVP_PKEY *client_priv = load_key("client_priv.pem",1);
    EVP_PKEY *server_pub  = load_key("server_pub.pem", 0);
    if(!client_priv||!server_pub){ fprintf(stderr,"Key load failed\n"); return 1; }

    int tap_fd = tap_open(TAP_DEV);
    if(tap_fd < 0) return 1;

    int sock = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in addr={0};
    addr.sin_family=AF_INET; addr.sin_port=htons(PORT);
    inet_pton(AF_INET,SERVER_IP,&addr.sin_addr);
    if(connect(sock,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("connect"); return 1; }
    printf("[NET] Connected to server %s:%d\n",SERVER_IP,PORT);

    /* ── handshake ── */
    EVP_PKEY *ceph = gen_x25519();
    uint8_t craw[32]; size_t l=32;
    EVP_PKEY_get_raw_public_key(ceph,craw,&l);
    send_all(sock,craw,32);

    uint8_t sraw[32]; recv_all(sock,sraw,32);
    EVP_PKEY *seph=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,sraw,32);

    uint8_t transcript[64];
    memcpy(transcript,craw,32); memcpy(transcript+32,sraw,32);

    uint8_t ssig[64]; recv_all(sock,ssig,64);
    EVP_MD_CTX *v=EVP_MD_CTX_new();
    EVP_DigestVerifyInit(v,NULL,NULL,NULL,server_pub);
    if(EVP_DigestVerify(v,ssig,64,transcript,64)<=0){ fprintf(stderr,"Server auth fail\n"); return 1; }
    EVP_MD_CTX_free(v);

    uint8_t csig[64]; size_t sl=64;
    EVP_MD_CTX *m=EVP_MD_CTX_new();
    EVP_DigestSignInit(m,NULL,NULL,NULL,client_priv);
    EVP_DigestSign(m,csig,&sl,transcript,64);
    send_all(sock,csig,64);
    EVP_MD_CTX_free(m);

    /* ── derive session key ── */
    tunnel_t tun = {0};
    tun.sock   = sock;
    tun.tap_fd = tap_fd;
    pthread_mutex_init(&tun.send_mutex,NULL);

    uint8_t secret[32], km[36];
    derive_secret(ceph,seph,secret);
    derive_hkdf(secret,32,transcript,64,km,36);
    memcpy(tun.key,km,32);
    memcpy(tun.fixed_nonce,km+32,4);
    OPENSSL_cleanse(secret,32); OPENSSL_cleanse(km,36);

    EVP_PKEY_free(client_priv); EVP_PKEY_free(server_pub);
    EVP_PKEY_free(ceph);        EVP_PKEY_free(seph);

    printf("[SEC] Secure channel established. Forwarding L2 frames...\n");

    /* ── start both threads ── */
    pthread_t tx, rx;
    pthread_create(&tx, NULL, tx_thread, &tun);
    pthread_create(&rx, NULL, rx_thread, &tun);
    pthread_join(tx, NULL);
    pthread_join(rx, NULL);

    OPENSSL_cleanse(tun.key,32);
    close(tap_fd); close(sock);
    return 0;
}