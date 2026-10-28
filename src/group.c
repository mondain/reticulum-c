#include <reticulum_c/rnc_security.h>
#include "internal.h"
#include "crypto_backend.h"
#include <string.h>

rnc_result rnc_group_generate(rnc_group_key *key,rnc_random_fn random,void *context) {
    rnc_group_key result={0};rnc_result status;
    if(!key||!random)return RNC_INVALID;
    status=random(context,result.bytes,sizeof(result.bytes));
    if(status==RNC_OK){result.valid=1;*key=result;}
    rnc_cleanse(&result,sizeof(result));return status;
}
rnc_result rnc_group_import(rnc_group_key *key,const uint8_t bytes[64]) {
    rnc_group_key result={0};if(!key||!bytes)return RNC_INVALID;
    memcpy(result.bytes,bytes,64);result.valid=1;*key=result;
    rnc_cleanse(&result,sizeof(result));return RNC_OK;
}
void rnc_group_clear(rnc_group_key *key){if(key)rnc_cleanse(key,sizeof(*key));}
rnc_result rnc_group_encrypt(const rnc_group_key *key,const void *data,size_t size,
    rnc_random_fn random,void *context,uint8_t *output,size_t capacity,size_t *written) {
    if(written)*written=0;
    if(!key||!key->valid||size>RNC_GROUP_MDU)return RNC_INVALID;
    return rnc_token_seal(key->bytes,data,size,random,context,output,capacity,written);
}
rnc_result rnc_group_decrypt(const rnc_group_key *key,const uint8_t *token,size_t size,
    uint8_t *output,size_t capacity,size_t *written) {
    if(written)*written=0;
    if(!key||!key->valid)return RNC_INVALID;
    if(size>48u+(RNC_GROUP_MDU/16u+1u)*16u)return RNC_AUTH;
    return rnc_token_open(key->bytes,token,size,output,capacity,written);
}
rnc_result rnc_plain_destination_hash(const char *dotted_name,uint8_t destination[16]) {
    uint8_t name[10];return rnc_destination_hash(dotted_name,NULL,name,destination);
}
