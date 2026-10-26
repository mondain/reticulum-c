#include <reticulum_c/rnc_security.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <limits.h>
#include <string.h>

static rnc_result derive(const uint8_t *input,size_t input_size,const uint8_t *salt,
    size_t salt_size,uint8_t *output,size_t size) {
    EVP_PKEY_CTX *ctx;size_t n=size;int ok;
    if(input_size>INT_MAX||salt_size>INT_MAX)return RNC_INVALID;
    ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL);
    ok=ctx&&EVP_PKEY_derive_init(ctx)==1&&EVP_PKEY_CTX_set_hkdf_md(ctx,EVP_sha256())==1&&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx,salt,(int)salt_size)==1&&
        EVP_PKEY_CTX_set1_hkdf_key(ctx,input,(int)input_size)==1&&
        EVP_PKEY_derive(ctx,output,&n)==1&&n==size;
    EVP_PKEY_CTX_free(ctx);return ok?RNC_OK:RNC_CRYPTO;
}
static int valid(const rnc_ifac *ifac) {
    return ifac&&ifac->size>0&&ifac->size<=RNC_IFAC_MAX_SIZE&&ifac->identity.has_private;
}
rnc_result rnc_ifac_init(rnc_ifac *ifac,const void *name,size_t name_size,
    const void *passphrase,size_t passphrase_size,size_t tag_size) {
    static const uint8_t salt[32]={0xad,0xf5,0x4d,0x88,0x2c,0x9a,0x9b,0x80,0x77,0x1e,0xb4,0x99,0x5d,0x70,0x2d,0x4a,0x3e,0x73,0x33,0x91,0xb2,0xa0,0xf5,0x3f,0x41,0x6d,0x9f,0x90,0x7e,0x55,0xcf,0xf8};
    rnc_ifac result={0};uint8_t material[64],hash[32];size_t n=0;rnc_result status;
    if(!ifac||(!name&&name_size)||(!passphrase&&passphrase_size)||
        (!name_size&&!passphrase_size)||!tag_size||tag_size>64)return RNC_INVALID;
    if(name_size) {status=rnc_hash(name,name_size,material+n);if(status!=RNC_OK)goto done;n+=32;}
    if(passphrase_size) {status=rnc_hash(passphrase,passphrase_size,material+n);if(status!=RNC_OK)goto done;n+=32;}
    status=rnc_hash(material,n,hash);if(status!=RNC_OK)goto done;
    status=derive(hash,32,salt,32,result.key,64);if(status!=RNC_OK)goto done;
    status=rnc_identity_from_private(&result.identity,result.key);if(status!=RNC_OK)goto done;
    result.size=tag_size;*ifac=result;
done:
    OPENSSL_cleanse(&result,sizeof(result));OPENSSL_cleanse(material,sizeof(material));
    OPENSSL_cleanse(hash,sizeof(hash));return status;
}
void rnc_ifac_clear(rnc_ifac *ifac) {if(ifac)OPENSSL_cleanse(ifac,sizeof(*ifac));}
rnc_result rnc_ifac_apply(const rnc_ifac *ifac,const uint8_t *raw,size_t size,
    uint8_t *output,size_t capacity,size_t *written) {
    uint8_t signature[64],mask[RNC_IFAC_FRAME_MAX],frame[RNC_IFAC_FRAME_MAX];
    rnc_packet packet;size_t total,i;rnc_result status;
    if(written)*written=0;
    if(!valid(ifac)||!raw||!output||!written)return RNC_INVALID;
    status=rnc_packet_decode(raw,size,&packet);if(status!=RNC_OK)return status;
    total=size+ifac->size;if(capacity<total)return RNC_NO_SPACE;
    status=rnc_identity_sign(&ifac->identity,raw,size,signature);if(status!=RNC_OK)goto done;
    status=derive(signature+64-ifac->size,ifac->size,ifac->key,64,mask,total);
    if(status!=RNC_OK)goto done;
    frame[0]=(uint8_t)((raw[0]^mask[0])|0x80u);frame[1]=(uint8_t)(raw[1]^mask[1]);
    memcpy(frame+2,signature+64-ifac->size,ifac->size);
    for(i=2;i<size;i++)frame[i+ifac->size]=(uint8_t)(raw[i]^mask[i+ifac->size]);
    memcpy(output,frame,total);*written=total;
done:
    OPENSSL_cleanse(signature,sizeof(signature));OPENSSL_cleanse(mask,sizeof(mask));
    OPENSSL_cleanse(frame,sizeof(frame));return status;
}
rnc_result rnc_ifac_verify(const rnc_ifac *ifac,const uint8_t *frame,size_t size,
    uint8_t *output,size_t capacity,size_t *written) {
    uint8_t signature[64],mask[RNC_IFAC_FRAME_MAX],raw[RNC_MAX_MTU];
    rnc_packet packet;size_t n,i;rnc_result status;
    if(written)*written=0;
    if(!valid(ifac)||!frame||!output||!written)return RNC_INVALID;
    if(size<=19u+ifac->size||size>RNC_MAX_MTU+ifac->size||!(frame[0]&0x80u))return RNC_AUTH;
    n=size-ifac->size;
    status=derive(frame+2,ifac->size,ifac->key,64,mask,size);if(status!=RNC_OK)goto done;
    raw[0]=(uint8_t)((frame[0]^mask[0])&0x7fu);raw[1]=(uint8_t)(frame[1]^mask[1]);
    for(i=2;i<n;i++)raw[i]=(uint8_t)(frame[i+ifac->size]^mask[i+ifac->size]);
    status=rnc_identity_sign(&ifac->identity,raw,n,signature);if(status!=RNC_OK)goto done;
    if(CRYPTO_memcmp(signature+64-ifac->size,frame+2,ifac->size)){status=RNC_AUTH;goto done;}
    status=rnc_packet_decode(raw,n,&packet);if(status!=RNC_OK)goto done;
    if(capacity<n){status=RNC_NO_SPACE;goto done;}
    memcpy(output,raw,n);*written=n;
done:
    OPENSSL_cleanse(signature,sizeof(signature));OPENSSL_cleanse(mask,sizeof(mask));
    OPENSSL_cleanse(raw,sizeof(raw));return status;
}
