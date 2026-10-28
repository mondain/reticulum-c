/*
 * Known-answer tests for the crypto backend linked into the library (openssl or
 * portable): NIST/RFC vectors for SHA-256, HMAC-SHA256, HKDF-SHA256, AES-256-CBC,
 * X25519 and Ed25519. Includes the internal backend header on purpose.
 */
#include "../src/crypto_backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(c)                                                                         \
    do {                                                                                 \
        if (!(c)) {                                                                      \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #c);        \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

static size_t unhex(const char *h, uint8_t *out) {
    size_t n = strlen(h) / 2, i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static int same_hex(const uint8_t *got, size_t n, const char *want) {
    uint8_t w[512];
    size_t m = unhex(want, w);
    return m == n && !memcmp(got, w, n);
}

static void test_sha256(void) {
    uint8_t d[32], big[1000];
    rnc_sha256_ctx c, c2;
    size_t i;
    CHECK(rnc_sha256("", 0, d) && same_hex(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK(rnc_sha256(NULL, 0, d) && same_hex(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK(rnc_sha256("abc", 3, d) && same_hex(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(rnc_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d) &&
          same_hex(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    /* one million 'a', fed in odd chunks */
    memset(big, 'a', sizeof(big));
    CHECK(rnc_sha256_init(&c));
    for (i = 0; i < 1000; i++) CHECK(rnc_sha256_update(&c, big, 1000));
    CHECK(rnc_sha256_final(&c, d) && same_hex(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    /* chunk boundaries around the 64 byte block and the 56 byte padding limit */
    for (i = 0; i < 1000; i++) big[i] = (uint8_t)i;
    for (i = 0; i <= 200; i++) {
        uint8_t one[32], split[32];
        size_t cut = i / 3;
        CHECK(rnc_sha256(big, i, one));
        CHECK(rnc_sha256_init(&c));
        CHECK(rnc_sha256_update(&c, big, cut));
        CHECK(rnc_sha256_copy(&c2, &c));
        CHECK(rnc_sha256_update(&c, big + cut, i - cut));
        CHECK(rnc_sha256_final(&c, split));
        CHECK(!memcmp(one, split, 32));
        CHECK(rnc_sha256_update(&c2, big + cut, i - cut));
        CHECK(rnc_sha256_final(&c2, split));
        CHECK(!memcmp(one, split, 32));
    }
    CHECK(rnc_sha256_init(&c));
    rnc_sha256_discard(&c);
}

static void test_hmac(void) {
    uint8_t key[200], data[200], d[32];
    size_t kn, dn;
    kn = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", key);
    CHECK(rnc_hmac_sha256(key, kn, "Hi There", 8, d) && same_hex(d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    CHECK(rnc_hmac_sha256((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, d) &&
          same_hex(d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);
    CHECK(rnc_hmac_sha256(key, 20, data, 50, d) && same_hex(d, 32, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
    kn = unhex("0102030405060708090a0b0c0d0e0f10111213141516171819", key);
    memset(data, 0xcd, 50);
    CHECK(rnc_hmac_sha256(key, kn, data, 50, d) && same_hex(d, 32, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));
    memset(key, 0xaa, 131);
    dn = strlen("Test Using Larger Than Block-Size Key - Hash Key First");
    CHECK(rnc_hmac_sha256(key, 131, "Test Using Larger Than Block-Size Key - Hash Key First", dn, d) &&
          same_hex(d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    dn = strlen("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    CHECK(rnc_hmac_sha256(key, 131,
              "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", dn, d) &&
          same_hex(d, 32, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
    /* digest-selecting variant used by the RPC handshake */
    {
        uint8_t o[64];
        size_t w = 0;
        CHECK(rnc_hmac_digest(RNC_DIGEST_SHA256, (const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, o, sizeof(o), &w) &&
              w == 32 && same_hex(o, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        CHECK(!rnc_hmac_digest(99, key, 4, "x", 1, o, sizeof(o), &w));
        /* RFC 2202 (MD5) and RFC 4231 (SHA-384) test case 2; the portable backend may
         * be built without these RPC-only digests, in which case it returns 0. */
        if (rnc_hmac_digest(RNC_DIGEST_MD5, (const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, o, sizeof(o), &w))
            CHECK(w == 16 && same_hex(o, 16, "750c783e6ab0b503eaa86e310a5db738"));
        if (rnc_hmac_digest(RNC_DIGEST_SHA384, (const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, o, sizeof(o), &w))
            CHECK(w == 48 && same_hex(o, 48, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"));
    }
}

static void test_hkdf(void) {
    uint8_t ikm[80], salt[80], info[80], out[82];
    size_t i;
    memset(ikm, 0x0b, 22);
    unhex("000102030405060708090a0b0c", salt);
    unhex("f0f1f2f3f4f5f6f7f8f9", info);
    CHECK(rnc_hkdf_sha256(salt, 13, ikm, 22, info, 10, out, 42) &&
          same_hex(out, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    for (i = 0; i < 80; i++) { ikm[i] = (uint8_t)i; salt[i] = (uint8_t)(0x60 + i); info[i] = (uint8_t)(0xb0 + i); }
    CHECK(rnc_hkdf_sha256(salt, 80, ikm, 80, info, 80, out, 82) &&
          same_hex(out, 82, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"));
    memset(ikm, 0x0b, 22);
    CHECK(rnc_hkdf_sha256(NULL, 0, ikm, 22, NULL, 0, out, 42) &&
          same_hex(out, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
    /* the shape the SDK uses: 16 byte salt, 32 byte secret, 64 byte output */
    CHECK(rnc_hkdf_sha256(salt, 16, ikm, 22, NULL, 0, out, 64));
}

static void test_aes(void) {
    uint8_t key[32], iv[16], pt[64], ct[64], back[64], buf[64];
    static const char *pt_hex = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    static const char *ct_hex = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b";
    unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key);
    unhex("000102030405060708090a0b0c0d0e0f", iv);
    unhex(pt_hex, pt);
    unhex(ct_hex, ct);
    CHECK(rnc_aes256_cbc_encrypt(key, iv, pt, back, 64) && !memcmp(back, ct, 64));
    CHECK(rnc_aes256_cbc_decrypt(key, iv, ct, back, 64) && !memcmp(back, pt, 64));
    memcpy(buf, pt, 64);
    CHECK(rnc_aes256_cbc_encrypt(key, iv, buf, buf, 64) && !memcmp(buf, ct, 64)); /* in place */
    CHECK(rnc_aes256_cbc_decrypt(key, iv, buf, buf, 64) && !memcmp(buf, pt, 64));
    CHECK(rnc_aes256_cbc_encrypt(key, iv, pt, back, 0));
    CHECK(!rnc_aes256_cbc_encrypt(key, iv, pt, back, 17));
    /* FIPS-197 C.3: single block, zero IV is plain AES-256 */
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key);
    unhex("00112233445566778899aabbccddeeff", pt);
    memset(iv, 0, 16);
    CHECK(rnc_aes256_cbc_encrypt(key, iv, pt, back, 16) && same_hex(back, 16, "8ea2b7ca516745bfeafc49904b496089"));
    CHECK(rnc_aes256_cbc_decrypt(key, iv, back, buf, 16) && !memcmp(buf, pt, 16));
}

static void test_x25519(void) {
    uint8_t a[32], u[32], out[32], pub[32], b[32];
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", a);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
    CHECK(rnc_x25519_derive(a, u, out) && same_hex(out, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", a);
    unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u);
    CHECK(rnc_x25519_derive(a, u, out) && same_hex(out, 32, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));
    /* RFC 7748 6.1 */
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b);
    CHECK(rnc_x25519_public(a, pub) && same_hex(pub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    CHECK(rnc_x25519_public(b, u) && same_hex(u, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    CHECK(rnc_x25519_derive(a, u, out) && same_hex(out, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    CHECK(rnc_x25519_derive(b, pub, out) && same_hex(out, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    /* low order point (u = 0) gives an all-zero secret and must be rejected */
    memset(u, 0, 32);
    CHECK(!rnc_x25519_derive(a, u, out));
    /* RFC 7748 5.2 iterated, 1 and 1000 rounds */
    {
        uint8_t k[32] = {9}, uu[32] = {9}, t[32];
        int i;
        for (i = 0; i < 1000; i++) {
            CHECK(rnc_x25519_derive(k, uu, t));
            memcpy(uu, k, 32);
            memcpy(k, t, 32);
            if (i == 0) CHECK(same_hex(k, 32, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
        }
        CHECK(same_hex(k, 32, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
    }
}

static void test_ed25519(void) {
    static const struct { const char *seed, *pub, *msg, *sig; } v[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
        {"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
         "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
         "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"}};
    size_t i;
    for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        uint8_t seed[32], pub[32], msg[64], sig[64], want[64], got[32];
        size_t mn;
        unhex(v[i].seed, seed);
        mn = unhex(v[i].msg, msg);
        unhex(v[i].sig, want);
        CHECK(rnc_ed25519_public(seed, got));
        unhex(v[i].pub, pub);
        CHECK(!memcmp(got, pub, 32));
        memcpy(pub, got, 32);
        CHECK(rnc_ed25519_sign(seed, msg, mn, sig) && !memcmp(sig, want, 64));
        CHECK(rnc_ed25519_verify(pub, msg, mn, sig));
        sig[10] ^= 1;
        CHECK(!rnc_ed25519_verify(pub, msg, mn, sig));
        sig[10] ^= 1;
        if (mn) {
            msg[0] ^= 1;
            CHECK(!rnc_ed25519_verify(pub, msg, mn, sig));
        }
        pub[0] ^= 1;
        CHECK(!rnc_ed25519_verify(pub, msg, mn, sig));
    }
}

static void test_misc(void) {
    uint8_t a[16], b[16];
    memset(a, 7, 16);
    memcpy(b, a, 16);
    CHECK(rnc_ct_memcmp(a, b, 16) == 0);
    b[15] ^= 0x80;
    CHECK(rnc_ct_memcmp(a, b, 16) != 0);
    b[15] ^= 0x80;
    b[0] ^= 1;
    CHECK(rnc_ct_memcmp(a, b, 16) != 0);
    CHECK(rnc_ct_memcmp(a, b, 0) == 0);
    rnc_cleanse(a, 16);
    {
        size_t i;
        for (i = 0; i < 16; i++) CHECK(a[i] == 0);
    }
}

int main(void) {
    test_sha256();
    test_hmac();
    test_hkdf();
    test_aes();
    test_x25519();
    test_ed25519();
    test_misc();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("crypto backend KATs passed");
    return 0;
}
