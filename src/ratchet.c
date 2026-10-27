#include <reticulum_c/rnc_security.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

static int public_key(const uint8_t private_key[32],uint8_t output[32]) {
    EVP_PKEY *key=EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,NULL,private_key,32);
    size_t n=32;int ok=key&&EVP_PKEY_get_raw_public_key(key,output,&n)==1&&n==32;
    EVP_PKEY_free(key);return ok;
}
static int valid(const rnc_ratchets *store) {
    return store&&store->keys&&store->capacity>0&&store->capacity<=RNC_RATCHET_MAX_KEYS&&
        store->count<=store->capacity&&store->interval>0&&store->last_time>=store->last_rotation;
}
static void write64(uint8_t *p,uint64_t n){size_t i;for(i=0;i<8;i++)p[7-i]=(uint8_t)(n>>(8*i));}
static uint64_t read64(const uint8_t *p){size_t i;uint64_t n=0;for(i=0;i<8;i++)n=(n<<8)|p[i];return n;}
rnc_result rnc_ratchet_generate(rnc_ratchet_key *key,uint64_t unix_seconds,
    rnc_random_fn random,void *context) {
    rnc_ratchet_key result={0};rnc_result status;
    if(!key||!random)return RNC_INVALID;
    status=random(context,result.private_key,32);if(status!=RNC_OK)goto done;
    if(!public_key(result.private_key,result.public_key)){status=RNC_CRYPTO;goto done;}
    result.created_at=unix_seconds;*key=result;
done:OPENSSL_cleanse(&result,sizeof(result));return status;
}
void rnc_ratchet_clear(rnc_ratchet_key *key){if(key)OPENSSL_cleanse(key,sizeof(*key));}
rnc_result rnc_ratchet_id(const uint8_t public_bytes[32],uint8_t id[10]) {
    uint8_t digest[32];rnc_result status;
    if(!public_bytes||!id)return RNC_INVALID;
    status=rnc_hash(public_bytes,32,digest);if(status==RNC_OK)memcpy(id,digest,10);return status;
}
rnc_result rnc_ratchets_init(rnc_ratchets *store,const rnc_identity *owner,
    rnc_ratchet_key *storage,size_t capacity,uint64_t interval_seconds) {
    rnc_ratchets result={0};
    if(!store||!owner||!storage||!capacity||capacity>RNC_RATCHET_MAX_KEYS||!interval_seconds)return RNC_INVALID;
    result.keys=storage;result.capacity=capacity;result.interval=interval_seconds;
    memcpy(result.owner_hash,owner->hash,16);
    OPENSSL_cleanse(storage,capacity*sizeof(*storage));*store=result;return RNC_OK;
}
void rnc_ratchets_clear(rnc_ratchets *store) {
    if(store){if(valid(store))OPENSSL_cleanse(store->keys,store->capacity*sizeof(*store->keys));OPENSSL_cleanse(store,sizeof(*store));}
}
rnc_result rnc_ratchets_rotate(rnc_ratchets *store,uint64_t unix_seconds,
    rnc_random_fn random,void *context) {
    rnc_ratchet_key key={0};rnc_result status;size_t retain,i;
    if(!valid(store)||!random||unix_seconds<store->last_time)return RNC_INVALID;
    if(store->count&&unix_seconds-store->last_rotation<store->interval){store->last_time=unix_seconds;return RNC_OK;}
    status=rnc_ratchet_generate(&key,unix_seconds,random,context);if(status!=RNC_OK)return status;
    for(i=0;i<store->count;i++)if(!CRYPTO_memcmp(key.public_key,store->keys[i].public_key,32)) {
        rnc_ratchet_clear(&key);return RNC_CRYPTO;
    }
    retain=store->count<store->capacity?store->count:store->capacity-1;
    if(retain)memmove(store->keys+1,store->keys,retain*sizeof(*store->keys));
    store->keys[0]=key;store->count=retain+1;store->last_rotation=store->last_time=unix_seconds;
    rnc_ratchet_clear(&key);return RNC_OK;
}
rnc_result rnc_ratchets_public(const rnc_ratchets *store,uint8_t public_bytes[32]) {
    if(!valid(store)||!public_bytes)return RNC_INVALID;
    if(!store->count)return RNC_AGAIN;
    memcpy(public_bytes,store->keys[0].public_key,32);return RNC_OK;
}
rnc_result rnc_ratchets_export(const rnc_ratchets *store,const rnc_identity *owner,
    uint8_t *output,size_t capacity,size_t *written) {
    uint8_t record[RNC_RATCHET_EXPORT_MAX];size_t n,i;rnc_result status;
    if(written)*written=0;
    if(!valid(store)||!owner||!owner->has_private||!output||!written||
        CRYPTO_memcmp(store->owner_hash,owner->hash,16))return RNC_INVALID;
    n=48u+40u*store->count;if(capacity<n+64u)return RNC_NO_SPACE;
    memset(record,0,48);memcpy(record,"RNCR",4);record[4]=1;
    record[6]=(uint8_t)(store->count>>8);record[7]=(uint8_t)store->count;
    write64(record+8,store->interval);write64(record+16,store->last_rotation);
    write64(record+24,store->last_time);memcpy(record+32,store->owner_hash,16);
    for(i=0;i<store->count;i++){write64(record+48u+40u*i,store->keys[i].created_at);memcpy(record+56u+40u*i,store->keys[i].private_key,32);}
    status=rnc_identity_sign(owner,record,n,record+n);
    if(status==RNC_OK){memcpy(output,record,n+64u);*written=n+64u;}
    OPENSSL_cleanse(record,sizeof(record));return status;
}
rnc_result rnc_ratchets_import(rnc_ratchets *store,const rnc_identity *owner,
    const uint8_t *record,size_t size) {
    uint8_t public_keys[RNC_RATCHET_MAX_KEYS][32];size_t count,n,i,j;uint64_t interval,last,seen,created,previous=0;
    rnc_result status=RNC_PROTOCOL;
    if(!valid(store)||!owner||!record)return RNC_INVALID;
    if(size<112u||size>RNC_RATCHET_EXPORT_MAX||memcmp(record,"RNCR",4)||record[4]!=1||record[5])return RNC_PROTOCOL;
    count=(size_t)record[6]*256u+record[7];n=48u+40u*count;
    if(count>RNC_RATCHET_MAX_KEYS||size!=n+64u)return RNC_PROTOCOL;
    if(count>store->capacity)return RNC_NO_SPACE;
    if(CRYPTO_memcmp(owner->hash,store->owner_hash,16)||CRYPTO_memcmp(owner->hash,record+32,16))return RNC_AUTH;
    status=rnc_identity_verify(owner,record,n,record+n);if(status!=RNC_OK)return status;
    interval=read64(record+8);last=read64(record+16);seen=read64(record+24);
    if(!interval||seen<last||(!count&&last))return RNC_PROTOCOL;
    if(store->count&&seen<store->last_time)return RNC_AUTH;
    memset(public_keys,0,sizeof(public_keys));
    for(i=0;i<count;i++) {
        created=read64(record+48u+40u*i);
        if((i==0&&created!=last)||(i&&created>previous)){status=RNC_PROTOCOL;goto done;}
        previous=created;
        if(!public_key(record+56u+40u*i,public_keys[i])){status=RNC_CRYPTO;goto done;}
        for(j=0;j<i;j++)if(!CRYPTO_memcmp(public_keys[j],public_keys[i],32)){status=RNC_PROTOCOL;goto done;}
    }
    OPENSSL_cleanse(store->keys,store->capacity*sizeof(*store->keys));
    for(i=0;i<count;i++) {
        store->keys[i].created_at=read64(record+48u+40u*i);
        memcpy(store->keys[i].private_key,record+56u+40u*i,32);
        memcpy(store->keys[i].public_key,public_keys[i],32);
    }
    store->count=count;store->interval=interval;
    store->last_rotation=last;store->last_time=seen;status=RNC_OK;
done:OPENSSL_cleanse(public_keys,sizeof(public_keys));return status;
}
rnc_result rnc_ratchet_encrypt(const rnc_identity *destination,
    const uint8_t ratchet_public[32],const void *data,size_t size,
    rnc_random_fn random,void *context,uint8_t *output,size_t capacity,size_t *written) {
    rnc_identity target;rnc_result status;
    if(written)*written=0;
    if(!destination||!ratchet_public)return RNC_INVALID;
    target=*destination;memcpy(target.public_key,ratchet_public,32);
    status=rnc_identity_encrypt(&target,data,size,random,context,output,capacity,written);
    rnc_identity_clear(&target);return status;
}
rnc_result rnc_ratchets_decrypt(const rnc_ratchets *store,const rnc_identity *owner,
    int enforce_ratchets,const uint8_t *token,size_t size,uint8_t *output,
    size_t capacity,size_t *written,uint8_t used_ratchet_id[10]) {
    rnc_identity receiver;size_t i;rnc_result status=RNC_AUTH;uint8_t id[10];
    if(written)*written=0;
    if(!valid(store)||!owner||!owner->has_private||!token||!output||!written||
        CRYPTO_memcmp(store->owner_hash,owner->hash,16))return RNC_INVALID;
    receiver=*owner;
    for(i=0;i<store->count;i++) {
        status=rnc_ratchet_id(store->keys[i].public_key,id);
        if(status!=RNC_OK)goto done;
        memcpy(receiver.private_key,store->keys[i].private_key,32);
        status=rnc_identity_decrypt(&receiver,token,size,output,capacity,written);
        if(status==RNC_OK) {
            if(used_ratchet_id)memcpy(used_ratchet_id,id,10);
            goto done;
        }
        if(status!=RNC_AUTH)goto done;
    }
    if(!enforce_ratchets) {
        status=rnc_identity_decrypt(owner,token,size,output,capacity,written);
        if(status==RNC_OK&&used_ratchet_id)memset(used_ratchet_id,0,10);
    }
done:rnc_identity_clear(&receiver);OPENSSL_cleanse(id,sizeof(id));return status;
}
rnc_result rnc_announce_create_ratchet(const rnc_identity *identity,
    const char *dotted_name,const uint8_t ratchet_public[32],const void *app_data,
    size_t app_size,uint64_t unix_seconds,rnc_random_fn random,void *context,
    rnc_packet *packet) {
    rnc_packet result;uint8_t signed_data[RNC_MTU];rnc_result status;
    if(!packet||!ratchet_public||app_size>284u)return RNC_INVALID;
    status=rnc_announce_create(identity,dotted_name,app_data,app_size,unix_seconds,random,context,&result);
    if(status!=RNC_OK)return status;
    if(app_size)memmove(result.data+180,result.data+148,app_size);
    memcpy(result.data+84,ratchet_public,32);result.flags|=0x20u;result.data_size=180u+app_size;
    memcpy(signed_data,result.destination,16);memcpy(signed_data+16,result.data,116);
    if(app_size)memcpy(signed_data+132,result.data+180,app_size);
    status=rnc_identity_sign(identity,signed_data,132u+app_size,result.data+116);
    if(status==RNC_OK)*packet=result;
    return status;
}
rnc_result rnc_peer_ratchet_remember(rnc_peer_ratchet *peer,
    const rnc_packet *packet,uint64_t unix_seconds) {
    rnc_announce announce;rnc_peer_ratchet result={0};uint64_t emitted=0;size_t i;rnc_result status;
    if(!peer||!packet||(peer->valid&&unix_seconds<peer->received_at))return RNC_INVALID;
    status=rnc_announce_verify(packet,&announce);if(status!=RNC_OK)return status;
    if(!announce.has_ratchet)return RNC_UNSUPPORTED;
    for(i=5;i<10;i++)emitted=(emitted<<8)|announce.random_hash[i];
    if(peer->valid&&(CRYPTO_memcmp(peer->destination,announce.destination,16)||emitted<peer->announced_at))return RNC_AUTH;
    /* Replaying or reannouncing the same key must not extend its lifetime. */
    if(peer->valid&&!CRYPTO_memcmp(peer->public_key,announce.ratchet,32)) {
        peer->announced_at=emitted;return RNC_OK;
    }
    memcpy(result.destination,announce.destination,16);memcpy(result.public_key,announce.ratchet,32);
    result.received_at=unix_seconds;result.announced_at=emitted;result.valid=1;*peer=result;return RNC_OK;
}
rnc_result rnc_peer_ratchet_public(const rnc_peer_ratchet *peer,
    uint64_t unix_seconds,uint8_t public_bytes[32]) {
    if(!peer||!public_bytes||(peer->valid&&unix_seconds<peer->received_at))return RNC_INVALID;
    if(!peer->valid)return RNC_AGAIN;
    if(unix_seconds-peer->received_at>=RNC_RATCHET_PEER_EXPIRY)return RNC_TIMEOUT;
    memcpy(public_bytes,peer->public_key,32);return RNC_OK;
}
void rnc_peer_ratchet_clear(rnc_peer_ratchet *peer){if(peer)OPENSSL_cleanse(peer,sizeof(*peer));}
