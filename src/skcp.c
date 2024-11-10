#include "skcp.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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
/*                               common function                              */
/* -------------------------------------------------------------------------- */
inline static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

inline static uint32_t getms() {
    return (uint32_t)(mstime() & 0xfffffffful);
}

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

/* -------------------------------------------------------------------------- */
/*                                    skcp                                    */
/* -------------------------------------------------------------------------- */

/* ------------------------------- private api ------------------------------ */

static int check_config(skcp_conf_t* conf) {
    if (!conf) {
        fprintf(stderr, "config error.\n");
        return _ERR;
    }
    if (conf->mode != SKCP_MODE_CLI && conf->mode != SKCP_MODE_SERV) {
        fprintf(stderr, "config 'mode' error. %d\n", conf->mode);
        return _ERR;
    }
    /*     if (conf->ip[0] == '\0' || conf->ip[INET_ADDRSTRLEN] != '\0') {
            fprintf(stderr, "config 'ip' error.\n");
            return _ERR;
        }
        if (conf->port > 65535 || conf->port <= 0) {
            fprintf(stderr, "config 'port' error. %u\n", conf->port);
            return _ERR;
        } */
    if (conf->kcp_mtu <= 0 || conf->kcp_mtu % AES_BLOCK_SIZE != 0) {
        conf->kcp_mtu = 1024;
        printf("config 'kcp_mtu' use default: %d\n", conf->kcp_mtu);
    }
    if (conf->kcp_rcvwnd <= 0) {
        conf->kcp_rcvwnd = 256;
        printf("config 'kcp_rcvwnd' use default: %d\n", conf->kcp_rcvwnd);
    }
    if (conf->kcp_sndwnd <= 0) {
        conf->kcp_sndwnd = 256;
        printf("config 'kcp_sndwnd' use default: %d\n", conf->kcp_sndwnd);
    }
    if (conf->kcp_nodelay != 0 || conf->kcp_nodelay != 1) {
        conf->kcp_nodelay = 1;
        printf("config 'kcp_nodelay' use default: %d\n", conf->kcp_nodelay);
    }
    if (conf->kcp_resend != 0 || conf->kcp_resend != 2) {
        conf->kcp_resend = 2;
        printf("config 'kcp_resend' use default: %d\n", conf->kcp_resend);
    }
    if (conf->kcp_nc != 0 || conf->kcp_nc != 1) {
        conf->kcp_nc = 1;
        printf("config 'kcp_nc' use default: %d\n", conf->kcp_nc);
    }
    if (conf->kcp_interval <= 0) {
        conf->kcp_interval = 20;
        printf("config 'ikcp_interval' use default: %d\n", conf->kcp_interval);
    }
    return _OK;
}

static int kcp_output(const char* buf, int len, struct IKCPCB* kcp, void* user) {
    skcp_conn_t* conn = (skcp_conn_t*)user;
    assert(conn);
    assert(conn->skcp);
    char* tmp_buf = (char*)buf;
    int tmp_len = len;
    /* TODO: */
    /*     if (conn->skcp->conf.key[0] != '\0') {
            int ret = aes_encrypt(conn->skcp->conf.key, buf, len, &conn->skcp->cipher_buf, &tmp_len);
            if (ret != _OK) return 0;
            assert(tmp_len <= conn->skcp->conf.kcp_mtu + AES_BLOCK_SIZE);
            tmp_buf = conn->skcp->cipher_buf;
            _LOG("encrypt");
        } */
    if (conn->skcp->conf.skcp_output_cb) {
        return conn->skcp->conf.skcp_output_cb(conn->skcp, conn->id, tmp_buf, tmp_len);
    }
    return 0;
}

/* ------------------------------- connection ------------------------------- */

static void free_conn(skcp_t* skcp, skcp_conn_t* conn) {
    assert(skcp);
    assert(conn);
    if (skcp->conn_tb) HASH_DEL(skcp->conn_tb, conn);
    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }
    conn->status = SKCP_CONN_ST_OFF;
    conn->id = 0;
    free(conn);
}

/* ------------------------------- public api ------------------------------- */

/* int skcp_send(skcp_t* skcp, uint32_t cid, const char* buf, int len) {
    if (!skcp || cid <= 0 || !buf || len <= 0) return _ERR;
    skcp_conn_t* conn = skcp_get_conn(skcp, cid);
    if (!conn || conn->status != SKCP_CONN_ST_ON) return _ERR;
    int n = len, ret = 0, bytes = 0;
    if (len / skcp->conf.mtu > 0) n = skcp->conf.mtu;
    while (n > 0) {
        ret = ikcp_send(conn->kcp, buf, n);
        if (ret < 0) return _ERR;
        n -= skcp->conf.mtu;
        bytes += ret;
    }
    ikcp_update(conn->kcp, getms());
    return bytes;
} */

int skcp_send(skcp_t* skcp, uint32_t cid, const char* buf, int len) {
    if (!skcp || cid <= 0 || !buf || len <= 0) return _ERR;
    skcp_conn_t* conn = skcp_get_conn(skcp, cid);
    if (!conn || conn->status != SKCP_CONN_ST_ON) return _ERR;
    int rt = ikcp_send(conn->kcp, buf, len);
    if (rt < 0) return _ERR;
    ikcp_update(conn->kcp, getms());
    return rt;
}

skcp_conn_t* skcp_get_conn(skcp_t* skcp, uint32_t cid) {
    if (!skcp || !skcp->conn_tb || cid <= 0) return NULL;
    skcp_conn_t* conn = NULL;
    HASH_FIND_INT(skcp->conn_tb, &cid, conn);
    return conn;
}

void skcp_close_conn(skcp_t* skcp, uint32_t cid) {
    skcp_conn_t* conn = skcp_get_conn(skcp, cid);
    if (!conn) return;
    free_conn(skcp, conn);
    _LOG("skcp_close_conn cid: %u", cid);
}

skcp_t* skcp_init(skcp_conf_t* conf, void* user_data) {
    if (check_config(conf) != _OK) return NULL;
    char key[SKCP_CIPHER_KEY_LEN + 1];
    memset(key, 0, sizeof(key));
    pwd2key(key, sizeof(key), conf->key, strlen(conf->key));
    memcpy(conf->key, key, sizeof(key));
    skcp_t* _ALLOC(skcp, skcp_t*, sizeof(skcp_t));
    memset(skcp, 0, sizeof(skcp_t));
    skcp->conf = *conf;
    skcp->user_data = user_data;
    skcp->conn_tb = NULL;
    /* skcp->fd = fd; */
    assert(skcp->conf.kcp_mtu % AES_BLOCK_SIZE == 0);
    _ALLOC(skcp->cipher_buf, char*, skcp->conf.kcp_mtu + AES_BLOCK_SIZE);
    memset(skcp->cipher_buf, 0, skcp->conf.kcp_mtu);
    return skcp;
}

void skcp_free(skcp_t* skcp) {
    if (!skcp) return;
    if (skcp->conn_tb) {
        skcp_conn_t *conn, *tmp;
        HASH_ITER(hh, skcp->conn_tb, conn, tmp) {
            HASH_DEL(skcp->conn_tb, conn);
            skcp_close_conn(skcp, conn->id);
        }
        skcp->conn_tb = NULL;
    }
    skcp->user_data = NULL;
    free(skcp);
}

void skcp_update(skcp_t* skcp, uint32_t cid) {
    skcp_conn_t* conn = skcp_get_conn(skcp, cid);
    if (!conn) return;
    ikcp_update(conn->kcp, getms());
    return;
}

uint32_t skcp_input(skcp_t* skcp, const char* buf, int len) {
    assert(len <= skcp->conf.kcp_mtu + AES_BLOCK_SIZE);
    if (len > skcp->conf.kcp_mtu) return _ERR;
    char* tmp_buf = (char*)buf;
    int tmp_len = len;
    /* TODO: */
    /*     if (skcp->conf.key[0] != '\0') {
            int ret = aes_decrypt(skcp->conf.key, buf, len, &skcp->cipher_buf, &tmp_len);
            if (ret != _OK) return _ERR;
            tmp_buf = skcp->cipher_buf;
            _LOG("decrypt");
        } */
    uint32_t cid = ikcp_getconv(tmp_buf);
    skcp_conn_t* conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        _LOG("skcp_input cid:%u does not exist", cid);
        return _ERR;
    }
    ikcp_input(conn->kcp, tmp_buf, tmp_len);
    ikcp_update(conn->kcp, getms());
    return cid;
}

skcp_conn_t* skcp_init_conn(skcp_t* skcp, int32_t cid /* , struct sockaddr_in target_addr */) {
    if (!skcp || cid <= 0) return NULL;
    skcp_conn_t* _ALLOC(conn, skcp_conn_t*, sizeof(skcp_conn_t));
    memset(conn, 0, sizeof(skcp_conn_t));
    ikcpcb* kcp = ikcp_create(cid, conn);
    if (kcp == NULL) {
        free(conn);
        _LOG("init skcp connection error. cid:%u", cid);
        return NULL;
    }
    conn->status = SKCP_CONN_ST_ON;
    conn->skcp = skcp;
    conn->id = cid;
    /* conn->target_sockaddr = target_addr; */
    HASH_ADD_INT(skcp->conn_tb, id, conn);
    kcp->output = kcp_output;
    ikcp_wndsize(kcp, skcp->conf.kcp_sndwnd, skcp->conf.kcp_rcvwnd);
    ikcp_nodelay(kcp, skcp->conf.kcp_nodelay, skcp->conf.kcp_interval, skcp->conf.kcp_nodelay, skcp->conf.kcp_nc);
    ikcp_setmtu(kcp, skcp->conf.kcp_mtu);
    conn->kcp = kcp;
    return conn;
}

/* return 0 for error, below 0 for EAGAIN */
int skcp_rcv(skcp_t* skcp, int32_t cid, char* buf, int len) {
    skcp_conn_t* conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        _LOG("skcp_rcv cid:%u does not exist", cid);
        return 0;
    }
    /* 返回-1表示数据还没有收完数据，-3表示接受buf太小 */
    int rlen = ikcp_recv(conn->kcp, buf, len);
    ikcp_update(conn->kcp, getms());
    return rlen;
}

int skcp_encrypt(const char* key, const char* in, int in_len, char** out, int* out_len) {
    return aes_encrypt(key, in, in_len, out, out_len);
}

int skcp_decrypt(const char* key, const char* in, int in_len, char** out, int* out_len) {
    return aes_decrypt(key, in, in_len, out, out_len);
}

uint32_t skcp_get_cid(const char* buf) {
    if (!buf) return 0;
    return ikcp_getconv(buf);
}
