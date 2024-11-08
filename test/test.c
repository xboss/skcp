#include <assert.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)

/* -------------------------------------------------------------------------- */
/*                                   cipher                                   */
/* -------------------------------------------------------------------------- */

/* static const int align_size = AES_BLOCK_SIZE; */
static int pkcs7_padding(const char* in, int in_len, char** out, int* out_len) {
    int remainder = in_len % AES_BLOCK_SIZE;
    int padding_size = remainder == 0 ? AES_BLOCK_SIZE : AES_BLOCK_SIZE - remainder;
    *out_len = in_len + padding_size;
    memcpy(*out, in, in_len);
    memset(*out + in_len, padding_size, padding_size);
    return _OK;
}

static int pkcs7_unpadding(const char* in, int in_len) {
    char padding_size = in[in_len - 1];
    return (int)padding_size;
}

static void pwd2key(char* key, int ken_len, const char* pwd, int pwd_len) {
    int i;
    int sum = 0;
    for (i = 0; i < pwd_len; i++) {
        sum += pwd[i];
    }
    int avg = sum / pwd_len;
    for (i = 0; i < ken_len; i++) {
        key[i] = pwd[i % pwd_len] ^ avg;
    }
}

static int aes_encrypt(const char* key, const char* in, int in_len, char** out, int* out_len) {
    if (!key || !in || in_len <= 0 || out == NULL || *out == NULL) {
        return _ERR;
    }
    AES_KEY aes_key;
    if (AES_set_encrypt_key((const unsigned char*)key, 128, &aes_key) < 0) {
        return _ERR;
    }
    int ret = pkcs7_padding(in, in_len, out, out_len);
    if (ret != _OK) return _ERR;
    char* pi = *out;
    char* po = *out;
    int en_len = 0;
    while (en_len < *out_len) {
        AES_encrypt((unsigned char*)pi, (unsigned char*)po, &aes_key);
        pi += AES_BLOCK_SIZE;
        po += AES_BLOCK_SIZE;
        en_len += AES_BLOCK_SIZE;
    }
    return _OK;
}

static int aes_decrypt(const char* key, const char* in, int in_len, char** out, int* out_len) {
    if (!key || !in || in_len <= 0 || out == NULL || *out == NULL) {
        return _ERR;
    }
    AES_KEY aes_key;
    if (AES_set_decrypt_key((const unsigned char*)key, 128, &aes_key) < 0) {
        return _ERR;
    }
    memset(*out, 0, in_len);
    char* po = *out;
    int en_len = 0;
    while (en_len < in_len) {
        AES_decrypt((unsigned char*)in, (unsigned char*)po, &aes_key);
        in += AES_BLOCK_SIZE;
        po += AES_BLOCK_SIZE;
        en_len += AES_BLOCK_SIZE;
    }
    *out_len = in_len - pkcs7_unpadding(*out, en_len);
    return _OK;
}

int main(int argc, char const* argv[]) {
    char msg[] = "1234567812345678";
    char* pwd = "passwordpassword";
    char key[16 + 1];
    memset(key, 0, sizeof(key));
    pwd2key(key, sizeof(key), pwd, strlen(pwd));

    _LOG("len:%ld msg:%s", strlen(msg), msg);

    int sz = 1024 + 16;
    char* _ALLOC(en, char*, sz);
    memset(en, 0, sz);
    int en_len = 0;

    int ret = aes_encrypt(key, msg, strlen(msg), &en, &en_len);
    assert(ret == _OK);
    _LOG("len:%d en:%s", en_len, en);

    char* _ALLOC(de, char*, sz);
    memset(de, 0, sz);
    int de_len = 0;

    ret = aes_decrypt(key, en, en_len, &de, &de_len);
    _LOG("len:%d de:%s", de_len, de);
    return 0;
}
