#include <reticulum_c/rnc_link.h>
#include <string.h>
static rnc_result random_bytes(void *context, uint8_t *output, size_t size) {
    unsigned *counter = context;
    size_t i;
    for (i = 0; i < size; ++i)
        output[i] = (uint8_t)(*counter)++;
    return RNC_OK;
}
int main(void) {
    rnc_identity identity;
    rnc_link *link;
    unsigned counter = 0;
    uint8_t token[RNC_MTU], plain[RNC_SINGLE_MDU];
    size_t size, used;
    static const char message[] = "installed and relocated C consumer";
    if (rnc_identity_generate(&identity, random_bytes, &counter) != RNC_OK)
        return 1;
    if (rnc_identity_encrypt(&identity, message, sizeof(message), random_bytes, &counter, token,
                             sizeof(token), &size) != RNC_OK)
        return 2;
    if (rnc_identity_decrypt(&identity, token, size, plain, sizeof(plain), &used) != RNC_OK ||
        used != sizeof(message) || memcmp(plain, message, used))
        return 3;
    link = rnc_link_new(random_bytes, &counter);
    if (!link || rnc_link_send(link, 1, message, sizeof(message), 0) != RNC_STATE)
        return 4;
    rnc_link_free(link);
    rnc_identity_clear(&identity);
    return 0;
}
