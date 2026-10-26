#include <reticulum_c/rnc_security.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)
static rnc_result rng(void *context,uint8_t *out,size_t n) {
    uint8_t *v=context; size_t i; for(i=0;i<n;i++)out[i]=(*v)++; return RNC_OK;
}
static rnc_result failed_rng(void *context,uint8_t *out,size_t n) { (void)context;(void)out;(void)n;return RNC_CRYPTO; }
static rnc_result counter_rng(void *context,uint8_t *out,size_t n) {
    uint64_t *counter=context;uint8_t seed[8],digest[32];size_t i,take;
    while(n){for(i=0;i<8;i++)seed[7-i]=(uint8_t)(*counter>>(8*i));++*counter;CHECK(rnc_hash(seed,sizeof(seed),digest)==RNC_OK);take=n<32?n:32;memcpy(out,digest,take);out+=take;n-=take;}
    return RNC_OK;
}
static void owner(rnc_identity *id,uint8_t first) { uint8_t key[64];size_t i;for(i=0;i<64;i++)key[i]=(uint8_t)(first+i);CHECK(rnc_identity_from_private(id,key)==RNC_OK); }
static int zero(const void *p,size_t n) { const uint8_t *b=p;size_t i;for(i=0;i<n;i++)if(b[i])return 0;return 1; }
static void resign_record(rnc_identity *id,uint8_t *record,size_t n) {CHECK(n>=64&&rnc_identity_sign(id,record,n-64,record+n-64)==RNC_OK);}
static void ifac_tests(void) {
    rnc_ifac a,b,saved;uint8_t raw[20]={8,0},frame[RNC_IFAC_FRAME_MAX],out[RNC_MTU],expected[64],material[64],hash[32];size_t n,w,i;
    EVP_PKEY_CTX *ctx;const uint8_t salt[32]={0xad,0xf5,0x4d,0x88,0x2c,0x9a,0x9b,0x80,0x77,0x1e,0xb4,0x99,0x5d,0x70,0x2d,0x4a,0x3e,0x73,0x33,0x91,0xb2,0xa0,0xf5,0x3f,0x41,0x6d,0x9f,0x90,0x7e,0x55,0xcf,0xf8};
    raw[19]=0x55;
    CHECK(rnc_ifac_init(&a,"mesh",4,"secret",6,8)==RNC_OK);
    /* Independently construct the specified digest/HKDF, not through rnc_ifac. */
    CHECK(EVP_Q_digest(NULL,"SHA256",NULL,"mesh",4,material,&n)&&n==32);
    CHECK(EVP_Q_digest(NULL,"SHA256",NULL,"secret",6,material+32,&n)&&n==32);
    CHECK(EVP_Q_digest(NULL,"SHA256",NULL,material,64,hash,&n)&&n==32);
    ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL);CHECK(ctx);
    CHECK(EVP_PKEY_derive_init(ctx)==1&&EVP_PKEY_CTX_set_hkdf_md(ctx,EVP_sha256())==1);
    CHECK(EVP_PKEY_CTX_set1_hkdf_salt(ctx,salt,32)==1&&EVP_PKEY_CTX_set1_hkdf_key(ctx,hash,32)==1);
    n=64;CHECK(EVP_PKEY_derive(ctx,expected,&n)==1&&n==64);EVP_PKEY_CTX_free(ctx);
    CHECK(!memcmp(expected,a.key,64));
    CHECK(rnc_ifac_apply(&a,raw,sizeof(raw),frame,sizeof(frame),&n)==RNC_OK&&n==28&&(frame[0]&0x80));
    CHECK(rnc_ifac_verify(&a,frame,n,out,sizeof(out),&w)==RNC_OK&&w==sizeof(raw)&&!memcmp(out,raw,w));
    for(i=0;i<n;i++) { frame[i]^=1;memset(out,0x5a,sizeof(out));w=99;CHECK(rnc_ifac_verify(&a,frame,n,out,sizeof(out),&w)!=RNC_OK&&w==0&&out[0]==0x5a);frame[i]^=1; }
    CHECK(rnc_ifac_init(&b,"mesh",4,"other",5,8)==RNC_OK);
    CHECK(rnc_ifac_verify(&b,frame,n,out,sizeof(out),&w)==RNC_AUTH&&w==0);
    for(i=0;i<n;i++) {memset(out,0x55,sizeof(out));CHECK(rnc_ifac_verify(&a,frame,i,out,sizeof(out),&w)!=RNC_OK&&w==0&&out[0]==0x55);}
    CHECK(rnc_ifac_apply(&a,raw,sizeof(raw),out,27,&w)==RNC_NO_SPACE&&w==0);
    CHECK(rnc_ifac_verify(&a,frame,n,out,19,&w)==RNC_NO_SPACE&&w==0);
    frame[0]&=0x7f;CHECK(rnc_ifac_verify(&a,frame,n,out,sizeof(out),&w)==RNC_AUTH);frame[0]|=0x80;
    saved=a;CHECK(rnc_ifac_init(&a,NULL,0,NULL,0,8)==RNC_INVALID&&!memcmp(&saved,&a,sizeof(a)));
    CHECK(rnc_ifac_init(&a,"x",1,NULL,0,0)==RNC_INVALID);
    for(i=1;i<=64;i++) {CHECK(rnc_ifac_init(&a,"mesh",4,NULL,0,i)==RNC_OK);CHECK(rnc_ifac_apply(&a,raw,sizeof(raw),frame,sizeof(frame),&n)==RNC_OK);CHECK(rnc_ifac_verify(&a,frame,n,out,sizeof(out),&w)==RNC_OK&&!memcmp(raw,out,w));}
    {uint8_t maximum[RNC_MTU]={8,0};memset(maximum+19,0x5a,RNC_MTU-19);CHECK(rnc_ifac_apply(&a,maximum,sizeof(maximum),frame,sizeof(frame),&n)==RNC_OK&&n==RNC_MTU+64);CHECK(rnc_ifac_verify(&a,frame,n,out,sizeof(out),&w)==RNC_OK&&w==RNC_MTU&&!memcmp(out,maximum,w));}
    {uint8_t maximum[RNC_MAX_MTU]={12,0},wide[RNC_MAX_MTU];memset(maximum+19,0x5a,RNC_MAX_MTU-19);CHECK(rnc_ifac_apply(&a,maximum,sizeof(maximum),frame,sizeof(frame),&n)==RNC_OK&&n==RNC_IFAC_FRAME_MAX);CHECK(rnc_ifac_verify(&a,frame,n,wide,sizeof(wide),&w)==RNC_OK&&w==RNC_MAX_MTU&&!memcmp(wide,maximum,w));maximum[0]=8;CHECK(rnc_ifac_apply(&a,maximum,sizeof(maximum),frame,sizeof(frame),&w)!=RNC_OK&&w==0);}
    rnc_ifac_clear(&a);rnc_ifac_clear(&b);CHECK(zero(&a,sizeof(a))&&zero(&b,sizeof(b)));
}
static void ratchet_tests(void) {
    rnc_identity id,other,pub;rnc_ratchet_key keys[2],copykeys[2],before[2];rnc_ratchets store,copy;
    rnc_peer_ratchet peer={0},saved_peer;rnc_packet ann;uint8_t random=1,p[32],token[500],plain[500],used[10],record[RNC_RATCHET_EXPORT_MAX],saved_record[RNC_RATCHET_EXPORT_MAX];size_t n,w,record_size,i;
    owner(&id,0);owner(&other,64);CHECK(rnc_identity_from_public(&pub,id.public_key)==RNC_OK);
    CHECK(rnc_ratchets_init(&store,&id,keys,2,10)==RNC_OK);
    CHECK(rnc_ratchets_public(&store,p)==RNC_AGAIN);
    CHECK(rnc_ratchets_rotate(&store,100,rng,&random)==RNC_OK&&store.count==1);
    CHECK(rnc_ratchets_public(&store,p)==RNC_OK);
    memcpy(before,keys,sizeof(keys));CHECK(rnc_ratchets_rotate(&store,109,rng,&random)==RNC_OK&&!memcmp(before,keys,sizeof(keys)));
    CHECK(rnc_ratchets_rotate(&store,99,rng,&random)==RNC_INVALID);
    CHECK(rnc_ratchet_encrypt(&pub,p,"voice",5,rng,&random,token,sizeof(token),&n)==RNC_OK);
    CHECK(rnc_identity_decrypt(&id,token,n,plain,sizeof(plain),&w)==RNC_AUTH);
    CHECK(rnc_ratchets_decrypt(&store,&id,1,token,n,plain,sizeof(plain),&w,used)==RNC_OK&&w==5&&!memcmp(plain,"voice",5));
    for(i=0;i<n;i++) {token[i]^=1;memset(plain,0x55,sizeof(plain));memset(used,0x33,sizeof(used));CHECK(rnc_ratchets_decrypt(&store,&id,1,token,n,plain,sizeof(plain),&w,used)!=RNC_OK&&w==0&&plain[0]==0x55&&used[0]==0x33);token[i]^=1;}
    CHECK(rnc_ratchets_decrypt(&store,&id,1,token,n,plain,4,&w,NULL)==RNC_NO_SPACE&&w==0);
    CHECK(rnc_ratchets_decrypt(&store,&id,1,token,n,plain,sizeof(plain),&w,used)==RNC_OK);
    CHECK(rnc_ratchet_id(p,plain)==RNC_OK&&!memcmp(used,plain,10));
    CHECK(rnc_ratchets_rotate(&store,110,failed_rng,NULL)==RNC_CRYPTO&&!memcmp(before,keys,sizeof(keys)));
    CHECK(rnc_ratchets_rotate(&store,110,rng,&random)==RNC_OK&&store.count==2);
    CHECK(rnc_ratchets_decrypt(&store,&id,1,token,n,plain,sizeof(plain),&w,NULL)==RNC_OK);
    CHECK(rnc_ratchets_export(&store,&id,record,sizeof(record),&record_size)==RNC_OK);
    CHECK(rnc_ratchets_init(&copy,&pub,copykeys,2,1)==RNC_OK);
    CHECK(rnc_ratchets_import(&copy,&pub,record,record_size)==RNC_OK&&copy.count==2&&!memcmp(copy.keys,store.keys,sizeof(keys))&&copy.interval==10);
    memcpy(saved_record,record,record_size);
    for(i=0;i<record_size;i++) {record[i]^=1;memcpy(before,copykeys,sizeof(before));CHECK(rnc_ratchets_import(&copy,&pub,record,record_size)!=RNC_OK&&!memcmp(before,copykeys,sizeof(before)));record[i]^=1;}
    CHECK(!memcmp(saved_record,record,record_size));
    memset(record+8,0,8);resign_record(&id,record,record_size);CHECK(rnc_ratchets_import(&copy,&id,record,record_size)==RNC_PROTOCOL);memcpy(record,saved_record,record_size);
    memcpy(record+96,record+56,32);resign_record(&id,record,record_size);CHECK(rnc_ratchets_import(&copy,&id,record,record_size)==RNC_PROTOCOL);memcpy(record,saved_record,record_size);
    CHECK(rnc_ratchets_import(&copy,&other,record,record_size)!=RNC_OK);
    CHECK(rnc_ratchets_rotate(&store,120,rng,&random)==RNC_OK&&store.count==2);
    CHECK(rnc_ratchets_decrypt(&store,&id,1,token,n,plain,sizeof(plain),&w,NULL)==RNC_AUTH);
    CHECK(rnc_ratchets_decrypt(&copy,&id,1,token,n,plain,sizeof(plain),&w,NULL)==RNC_OK);
    CHECK(rnc_ratchets_rotate(&copy,130,rng,&random)==RNC_OK);
    CHECK(rnc_ratchets_import(&copy,&id,record,record_size)==RNC_AUTH);
    CHECK(rnc_identity_encrypt(&pub,"base",4,rng,&random,token,sizeof(token),&n)==RNC_OK);
    CHECK(rnc_ratchets_decrypt(&store,&id,1,token,n,plain,sizeof(plain),&w,NULL)==RNC_AUTH);
    CHECK(rnc_ratchets_decrypt(&store,&id,0,token,n,plain,sizeof(plain),&w,used)==RNC_OK&&w==4&&!memcmp(plain,"base",4)&&zero(used,10));
    CHECK(rnc_announce_create_ratchet(&id,"test.ratchet",p,"hi",2,100,rng,&random,&ann)==RNC_OK);
    CHECK(rnc_peer_ratchet_remember(&peer,&ann,100)==RNC_OK);
    CHECK(rnc_peer_ratchet_remember(&peer,&ann,101)==RNC_OK&&peer.received_at==100);
    CHECK(rnc_peer_ratchet_public(&peer,100,p)==RNC_OK&&!memcmp(p,ann.data+84,32));
    CHECK(rnc_peer_ratchet_public(&peer,100+RNC_RATCHET_PEER_EXPIRY,p)==RNC_TIMEOUT);
    CHECK(rnc_peer_ratchet_public(&peer,99,p)==RNC_INVALID);
    saved_peer=peer;ann.data[100]^=1;CHECK(rnc_peer_ratchet_remember(&peer,&ann,101)==RNC_AUTH&&!memcmp(&saved_peer,&peer,sizeof(peer)));
    rnc_peer_ratchet_clear(&peer);CHECK(zero(&peer,sizeof(peer)));
    rnc_ratchets_clear(&store);rnc_ratchets_clear(&copy);CHECK(zero(keys,sizeof(keys))&&zero(copykeys,sizeof(copykeys)));
    {rnc_ratchet_key *large=calloc(RNC_RATCHET_MAX_KEYS,sizeof(*large)),*restored=calloc(RNC_RATCHET_MAX_KEYS,sizeof(*restored));uint64_t counter=0;
     CHECK(large&&restored&&rnc_ratchets_init(&store,&id,large,RNC_RATCHET_MAX_KEYS,1)==RNC_OK&&rnc_ratchets_init(&copy,&pub,restored,RNC_RATCHET_MAX_KEYS,1)==RNC_OK);
     for(i=0;i<RNC_RATCHET_MAX_KEYS;i++)CHECK(rnc_ratchets_rotate(&store,100+i,counter_rng,&counter)==RNC_OK);
     CHECK(store.count==RNC_RATCHET_MAX_KEYS&&rnc_ratchets_export(&store,&id,record,sizeof(record),&record_size)==RNC_OK&&record_size==RNC_RATCHET_EXPORT_MAX);
     CHECK(rnc_ratchets_import(&copy,&pub,record,record_size)==RNC_OK&&!memcmp(large,restored,RNC_RATCHET_MAX_KEYS*sizeof(*large)));
     rnc_ratchets_clear(&store);rnc_ratchets_clear(&copy);free(large);free(restored);}
}
static void group_tests(void) {
    rnc_group_key a,b,saved;uint8_t random=3,token[500],plain[500],rawkey[64],hash[32],dest[16];size_t n,w,i;
    CHECK(rnc_group_generate(&a,rng,&random)==RNC_OK);memcpy(rawkey,a.bytes,64);CHECK(rnc_group_import(&b,rawkey)==RNC_OK);
    CHECK(rnc_group_encrypt(&a,"group",5,rng,&random,token,sizeof(token),&n)==RNC_OK);
    CHECK(rnc_group_decrypt(&b,token,n,plain,sizeof(plain),&w)==RNC_OK&&w==5&&!memcmp(plain,"group",5));
    for(i=0;i<n;i++) {token[i]^=1;memset(plain,0x55,sizeof(plain));CHECK(rnc_group_decrypt(&b,token,n,plain,sizeof(plain),&w)!=RNC_OK&&w==0&&plain[0]==0x55);token[i]^=1;}
    saved=a;CHECK(rnc_group_generate(&a,failed_rng,NULL)==RNC_CRYPTO&&!memcmp(&a,&saved,sizeof(a)));
    memset(plain,0x5a,RNC_GROUP_MDU);CHECK(rnc_group_encrypt(&a,plain,RNC_GROUP_MDU,rng,&random,token,sizeof(token),&n)==RNC_OK);CHECK(rnc_group_decrypt(&b,token,n,plain,sizeof(plain),&w)==RNC_OK&&w==RNC_GROUP_MDU);
    CHECK(rnc_group_encrypt(&a,plain,RNC_GROUP_MDU+1,rng,&random,token,sizeof(token),&n)==RNC_INVALID&&n==0);
    CHECK(rnc_group_encrypt(&a,NULL,0,rng,&random,token,sizeof(token),&n)==RNC_OK);CHECK(rnc_group_decrypt(&b,token,n,plain,sizeof(plain),&w)==RNC_OK&&w==0);
    CHECK(rnc_plain_destination_hash("rnstransport.path.request",dest)==RNC_OK);CHECK(rnc_hash("rnstransport.path.request",25,hash)==RNC_OK);CHECK(rnc_hash(hash,10,plain)==RNC_OK&&!memcmp(dest,plain,16));
    rnc_group_clear(&a);rnc_group_clear(&b);CHECK(zero(&a,sizeof(a))&&zero(&b,sizeof(b)));
}
int main(int argc,char **argv) {if(argc!=2)return 2;if(!strcmp(argv[1],"ifac"))ifac_tests();else if(!strcmp(argv[1],"ratchet"))ratchet_tests();else if(!strcmp(argv[1],"group"))group_tests();else return 2;return 0;}
