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

inline static uint32_t getms() { return (uint32_t)(mstime() & 0xfffffffful); }

// inline static void build_iv(char *iv, const uint32_t cid, const char *ticket) {
//     char iv_str[SKCP_IV_LEN + 1] = {0};
//     snprintf(iv_str, SKCP_IV_LEN + 1, "%u", cid);
//     for (size_t i = strlen(iv_str); i < SKCP_IV_LEN && i < SKCP_TICKET_LEN; i++) {
//         iv_str[i] = ticket[i];
//     }
// }

/* -------------------------------------------------------------------------- */
/*                                   cipher                                   */
/* -------------------------------------------------------------------------- */

static const int align_size = AES_BLOCK_SIZE;
static char *pkcs7_padding(const char *in, int in_len, int *out_len) {
    int remainder = in_len % align_size;
    int padding_size = remainder == 0 ? align_size : align_size - remainder;
    *out_len = in_len + padding_size;
    char *out = (char *)malloc(*out_len);
    if (!out) {
        perror("alloc error");
        return NULL;
    }
    memcpy(out, in, in_len);
    memset(out + in_len, padding_size, padding_size);
    return out;
}

static int pkcs7_unpadding(const char *in, int in_len) {
    char padding_size = in[in_len - 1];
    return (int)padding_size;
}

static void pwd2key(char *key, int ken_len, const char *pwd, int pwd_len) {
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

static char *aes_encrypt(const char *key, const char *in, int in_len, int *out_len) {
    if (!key || !in || in_len <= 0) {
        return NULL;
    }
    AES_KEY aes_key;
    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        return NULL;
    }
    char *out = pkcs7_padding(in, in_len, out_len);
    char *pi = out;
    char *po = out;
    int en_len = 0;
    while (en_len < *out_len) {
        AES_encrypt((unsigned char *)pi, (unsigned char *)po, &aes_key);
        pi += AES_BLOCK_SIZE;
        po += AES_BLOCK_SIZE;
        en_len += AES_BLOCK_SIZE;
    }
    return out;
}

static char *aes_decrypt(const char *key, const char *in, int in_len, int *out_len) {
    if (!key || !in || in_len <= 0) {
        return NULL;
    }
    AES_KEY aes_key;
    if (AES_set_decrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        return NULL;
    }
    char *out = malloc(in_len);
    if (!out) {
        perror("alloc error");
        return NULL;
    }
    memset(out, 0, in_len);
    char *po = out;
    int en_len = 0;
    while (en_len < in_len) {
        AES_decrypt((unsigned char *)in, (unsigned char *)po, &aes_key);
        in += AES_BLOCK_SIZE;
        po += AES_BLOCK_SIZE;
        en_len += AES_BLOCK_SIZE;
    }
    *out_len = in_len - pkcs7_unpadding(out, en_len);
    return out;
}

/* -------------------------------------------------------------------------- */
/*                                    skcp                                    */
/* -------------------------------------------------------------------------- */

/* ------------------------------- private api ------------------------------ */

static int check_config() {
    /* TODO: */
    return _OK;
}

static int kcp_output(const char *buf, int len, struct IKCPCB *kcp, void *user) {
    skcp_conn_t *conn = (skcp_conn_t *)user;
    assert(conn);
    assert(conn->skcp);
    if (conn->skcp->conf.skcp_output_cb) {
        /* TODO: encrypt */
        return conn->skcp->conf.skcp_output_cb(conn->skcp, conn->id, buf, len);
    }
    return 0;
}

/* ------------------------------- connection ------------------------------- */

static skcp_conn_t *init_conn(skcp_t *skcp, int32_t cid, struct sockaddr_in target_addr) {
    if (!skcp || cid <= 0) {
        return NULL;
    }

    skcp_conn_t *_ALLOC(conn, skcp_conn_t *, sizeof(skcp_conn_t));
    ikcpcb *kcp = ikcp_create(cid, conn);
    if (kcp == NULL) {
        free(conn);
        _LOG("init skcp connection error. cid:%u", cid);
        return NULL;
    }
    conn->last_r_tm = conn->last_w_tm = mstime();
    conn->status = SKCP_CONN_ST_ON;
    conn->skcp = skcp;
    conn->id = cid;
    conn->target_addr = target_addr;
    HASH_ADD_INT(skcp->conn_tb, id, conn);
    kcp->output = kcp_output;
    ikcp_wndsize(kcp, skcp->conf.sndwnd, skcp->conf.rcvwnd);
    ikcp_nodelay(kcp, skcp->conf.nodelay, skcp->conf.interval, skcp->conf.nodelay, skcp->conf.nc);
    ikcp_setmtu(kcp, skcp->conf.mtu);
    conn->kcp = kcp;
    return conn;
}

static void free_conn(skcp_t *skcp, skcp_conn_t *conn) {
    assert(skcp);
    assert(conn);
    if (skcp->conn_tb) {
        HASH_DEL(skcp->conn_tb, conn);
    }
    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }
    conn->status = SKCP_CONN_ST_OFF;
    conn->id = 0;
    free(conn);
}

/* ------------------------------- public api ------------------------------- */

int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, int len) {
    if (!skcp || cid <= 0 || !buf || len <= 0) return _ERR;
    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn || conn->status != SKCP_CONN_ST_ON) return _ERR;
    /* TODO: encrypt */
    int rt = ikcp_send(conn->kcp, buf, len);
    if (rt < 0) return _ERR;
    ikcp_update(conn->kcp, getms());
    return rt;
}

skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid) {
    if (!skcp || !skcp->conn_tb || cid <= 0) {
        return NULL;
    }
    skcp_conn_t *conn = NULL;
    HASH_FIND_INT(skcp->conn_tb, &cid, conn);
    return conn;
}

void skcp_close_conn(skcp_t *skcp, uint32_t cid) {
    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        return;
    }
    free_conn(skcp, conn);
    _LOG("skcp_close_conn cid: %u", cid);
}

skcp_t *skcp_init(int fd, skcp_conf_t *conf, void *user_data) {
    if (check_config(conf) != _OK) {
        return NULL;
    }
    skcp_t *_ALLOC(skcp, skcp_t *, sizeof(skcp_t));
    skcp->conf = *conf;
    skcp->user_data = user_data;
    skcp->conn_tb = NULL;
    skcp->fd = fd;
    return skcp;
}

void skcp_free(skcp_t *skcp) {
    if (!skcp) {
        return;
    }
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

void skcp_update(skcp_t *skcp, uint32_t cid) {
    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        return;
    }
    ikcp_update(conn->kcp, getms());
    return;
}

int skcp_input(skcp_t *skcp, uint32_t cid, const char *buf, int len) {
    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        return _ERR;
    }
    ikcp_input(conn->kcp, buf, len);
    ikcp_update(conn->kcp, getms());
    return _OK;
}
