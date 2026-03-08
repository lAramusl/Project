#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <endian.h>

#define PORT 1112
#define BUF 2048

int send_all(int fd, uint8_t *buf,int len)
    {
        int total=0;
        while(total<len)
        {
            int s=send(fd,buf+total,len-total,0);
            if(s<=0)return -1;
            total+=s;
        }
        return total;
    }
int recv_all(int fd,   uint8_t *buf,int len)
{
    int total=0;
    while(total<len){
        int r=recv(fd,buf+total,len-total,0);
        if(r<=0)return -1;
        total+=r;
    }
    return total;
}

EVP_PKEY* load_key(const char* file,int priv){
    FILE* f=fopen(file,"r");
    if(!f)return NULL;
    EVP_PKEY* k=priv?PEM_read_PrivateKey(f,NULL,NULL,NULL):PEM_read_PUBKEY(f,NULL,NULL,NULL);
    fclose(f);
    return k;
}
EVP_PKEY* gen_x25519(){
     EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
     EVP_PKEY *pkey=NULL; 
     EVP_PKEY_keygen_init(ctx); 
     EVP_PKEY_keygen(ctx,&pkey); 
     EVP_PKEY_CTX_free(ctx); 
     return pkey;
    
}
int derive_secret(EVP_PKEY* priv, EVP_PKEY* peer,uint8_t* out){
    EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new(priv,NULL); 
    size_t len=32; 
    EVP_PKEY_derive_init(ctx); 
    EVP_PKEY_derive_set_peer(ctx,peer);
     EVP_PKEY_derive(ctx,out,&len);
      EVP_PKEY_CTX_free(ctx); 
      return (int)len;
}
int derive_modern_hkdf(const uint8_t *secret,
                           size_t secret_len,const uint8_t *salt,size_t salt_len,
                         uint8_t *out,size_t out_len)
{
      EVP_KDF *kdf=EVP_KDF_fetch(NULL,"HKDF",NULL);
      EVP_KDF_CTX *kctx=EVP_KDF_CTX_new(kdf); 
      OSSL_PARAM params[5],*p=params;
      *p++=OSSL_PARAM_construct_utf8_string("digest","SHA256",0);
      *p++=OSSL_PARAM_construct_octet_string("key",(void*)secret,secret_len);
      *p++=OSSL_PARAM_construct_octet_string("salt",(void*)salt,salt_len);
      *p++=OSSL_PARAM_construct_octet_string("info","MySecureApp-v1",14);
      *p=OSSL_PARAM_construct_end();
       int ret=(EVP_KDF_derive(kctx,out,out_len,params)>0)?0:-1;
       EVP_KDF_CTX_free(kctx);
       EVP_KDF_free(kdf);
       
       return ret;
    
}
int encrypt_msg_with_seq(uint8_t* key,uint8_t* pt,int plen,
                            uint8_t* fixed_nonce,uint64_t seq_num,
                           uint8_t* ct,uint8_t* tag)
                           {
       EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
       int len,clen;
       uint8_t iv[12];
       memcpy(iv,fixed_nonce,4);
       // iv  = 12 byte 
    // iv =  fixed_nonce(4 byte) | sequence_number(8 byte)
       for(int i=0;i<8;i++)
             iv[4+i]=(seq_num>>(56-(i*8)))&0xFF;

       EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,iv);
       EVP_EncryptUpdate(ctx,ct,&len,pt,plen);
       clen=len;
       EVP_EncryptFinal_ex(ctx,ct+len,&len);
       clen+=len;
       EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,tag);
       EVP_CIPHER_CTX_free(ctx);
       
       return clen;
    }
int decrypt_msg_with_seq(uint8_t* key,uint8_t* ct,int clen,
                           uint8_t* fixed_nonce,uint64_t seq_num,uint8_t* tag,uint8_t* pt)
 {
        EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
        int len,plen;
        uint8_t iv[12];
        // iv  = 12 byte 
        // iv =  fixed_nonce(4 byte) | sequence_number(8 byte)   
        memcpy(iv,fixed_nonce,4);
        
        for(int i=0;i<8;i++)
            iv[4+i]=(seq_num>>(56-(i*8)))&0xFF;
        
        EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,iv);
        EVP_DecryptUpdate(ctx,pt,&len,ct,clen);
        plen=len;
        EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,tag);
        int res=EVP_DecryptFinal_ex(ctx,pt+len,&len);
        EVP_CIPHER_CTX_free(ctx);
        
        return (res>0)?(plen+len):-1;
    
}

int main(){
    EVP_PKEY* server_priv=load_key("server_priv.pem",1);
    EVP_PKEY* client_pub=load_key("client_pub.pem",0);
    if(!server_priv || !client_pub){printf("Key error\n");return 1;}

    int s=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a={0};
    a.sin_family=AF_INET; 
    a.sin_port=htons(PORT);
    a.sin_addr.s_addr=INADDR_ANY;
    bind(s,(void*)&a,sizeof(a)); 
    listen(s,1);
    printf("Listening on %d...\n",PORT);

    int c=accept(s,NULL,NULL);

    uint8_t client_raw[32]; 
    recv_all(c,client_raw,32);
    EVP_PKEY* client_eph=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,client_raw,32);

    EVP_PKEY* server_eph=gen_x25519(); 
    uint8_t server_raw[32]; 
    size_t l=32;
    EVP_PKEY_get_raw_public_key(server_eph,server_raw,&l);
    send_all(c,server_raw,32);

    uint8_t transcript[64], sig[64]; 
    size_t siglen=64;
    memcpy(transcript,client_raw,32);
    memcpy(transcript+32,server_raw,32);

    EVP_MD_CTX* m=EVP_MD_CTX_new();
    EVP_DigestSignInit(m,NULL,NULL,NULL,server_priv);
    EVP_DigestSign(m,sig,&siglen,transcript,64);
    send_all(c,sig,(int)siglen);
    EVP_MD_CTX_free(m);

    uint8_t client_sig[64]; 
    recv_all(c,client_sig,64);
    EVP_MD_CTX* v=EVP_MD_CTX_new();
    EVP_DigestVerifyInit(v,NULL,NULL,NULL,client_pub);

    if(EVP_DigestVerify(v,client_sig,64,transcript,64)<=0)
    {   printf("Auth failed\n");
        return 1;
    }
    EVP_MD_CTX_free(v);

    uint8_t secret[32], key[32], fixed_nonce[4],  key_material[36];

    derive_secret(server_eph,client_eph,secret);
    derive_modern_hkdf(secret,32, transcript,64, key_material,36);
    memcpy(key, key_material,32);
    memcpy(fixed_nonce, key_material+32,4);

    printf("Secure channel established.\n");

    uint64_t send_seq=0, recv_seq=0;

        uint8_t tag[16], ct[BUF], pt[BUF];
        int n, clen;

        // RECEIVE
        //     +----------------+--------------------+----------------+
        //     | Sequence (8B)  | Ciphertext (n B)   | Tag (16 B)     |
        //     +----------------+--------------------+----------------+
        //     byte 0           byte 8               ... byte total_len+15

uint8_t seq_buf[8];
uint32_t net_len;

/* receive sequence */
if(recv_all(c, seq_buf, 8)<=0) return 0;

uint64_t rseq = 0;
for(int i=0;i<8;i++)
    rseq = (rseq<<8) | seq_buf[i];

/* receive ciphertext length */
if(recv_all(c,(uint8_t*)&net_len,4)<=0) return 0;

clen = ntohl(net_len);
if(clen<=0 || clen>BUF) return 0;

/* receive ciphertext */
if(recv_all(c,ct,clen)<=0) return 0;

/* receive tag */
if(recv_all(c,tag,16)<=0) return 0;

/* decrypt */
int plen = decrypt_msg_with_seq(
                key,ct,clen,
                fixed_nonce,rseq,
                tag,pt);

if(plen < 0){
    printf("Integrity fail!\n");
    return 0;
}

pt[plen] = 0;
printf("Client: %s\n", pt);
close(c);
close(s);
return 0;
}      
      