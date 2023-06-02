#ifndef _SKCP_COMMON_H
#define _SKCP_COMMON_H

#include <arpa/inet.h>
#include <assert.h>
#include <ev.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

// typedef unsigned char u_char;
// typedef unsigned int uint;

#define SKCP_OK 0
#define SKCP_ERR -1

#define SKCP_ALLOC(element_size) calloc(1, element_size)

#define SKCP_FREEIF(p) \
    do {               \
        if (p) {       \
            free(p);   \
            p = NULL;  \
        }              \
    } while (0)

#define SKCP_LOG(fmt, args...) \
    do {                       \
        printf(fmt, ##args);   \
        printf("\n");          \
    } while (0)

#define SKCP_MAX_CONNS 1024

#define SKCP_MSG_TYPE_DATA 0x1
#define SKCP_MSG_TYPE_UDP 0x2
#define SKCP_MSG_TYPE_INPUT 0x3
#define SKCP_MSG_TYPE_SEND 0x4
#define SKCP_MSG_TYPE_RECV 0x5
#define SKCP_MSG_TYPE_CLOSE_TIMEOUT 0x6
#define SKCP_MSG_TYPE_CLOSE_MANUAL 0x7

/*
#define SKCP_INIT_MSG(_v_msg, _v_type, _v_cid, _v_buf, _v_buf_len, _v_user_data) \
    do {                                                                         \
        (_v_msg) = (skcp_msg_t *)SKCP_ALLOC(sizeof(skcp_msg_t));                 \
        (_v_msg)->type = (_v_type);                                              \
        if ((_v_buf_len) > 0 && (_v_buf) != NULL) {                              \
            (_v_msg)->buf_len = (_v_buf_len);                                    \
            (_v_msg)->buf = (char *)SKCP_ALLOC((_v_buf_len));                    \
            memcpy((_v_msg)->buf, (_v_buf), (_v_buf_len));                       \
        } else {                                                                 \
            (_v_msg)->buf = NULL;                                                \
            (_v_msg)->buf_len = 0;                                               \
        }                                                                        \
        (_v_msg)->cid = (_v_cid);                                                \
        (_v_msg)->user_data = (_v_user_data);                                    \
    } while (0)

#define SKCP_INIT_IO_MSG(_v_msg, _v_type, _v_dst_addr, _v_buf, _v_buf_len, _v_user_data) \
    do {                                                                                 \
        (_v_msg) = (skcp_msg_t *)SKCP_ALLOC(sizeof(skcp_msg_t));                         \
        (_v_msg)->type = (_v_type);                                                      \
        if ((_v_buf_len) > 0 && (_v_buf) != NULL) {                                      \
            (_v_msg)->buf_len = (_v_buf_len);                                            \
            (_v_msg)->buf = (char *)SKCP_ALLOC((_v_buf_len));                            \
            memcpy((_v_msg)->buf, (_v_buf), (_v_buf_len));                               \
        } else {                                                                         \
            (_v_msg)->buf = NULL;                                                        \
            (_v_msg)->buf_len = 0;                                                       \
        }                                                                                \
        (_v_msg)->dst_addr = (_v_dst_addr);                                              \
        (_v_msg)->user_data = (_v_user_data);                                            \
    } while (0)

#define SKCP_INIT_ENGINE_MSG(_v_msg, _v_type, _v_cid, _v_buf, _v_buf_len, _v_user_data) \
    do {                                                                                \
        (_v_msg) = (skcp_msg_t *)SKCP_ALLOC(sizeof(skcp_msg_t));                        \
        (_v_msg)->type = (_v_type);                                                     \
        if ((_v_buf_len) > 0 && (_v_buf) != NULL) {                                     \
            (_v_msg)->buf_len = (_v_buf_len);                                           \
            (_v_msg)->buf = (char *)SKCP_ALLOC((_v_buf_len));                           \
            memcpy((_v_msg)->buf, (_v_buf), (_v_buf_len));                              \
        } else {                                                                        \
            (_v_msg)->buf = NULL;                                                       \
            (_v_msg)->buf_len = 0;                                                      \
        }                                                                               \
        (_v_msg)->cid = (_v_cid);                                                       \
        (_v_msg)->user_data = (_v_user_data);                                           \
    } while (0)

*/
typedef struct {
    u_char type;
    char *buf;
    size_t buf_len;
    uint32_t cid;
    struct sockaddr_in dst_addr;
    // struct sockaddr dst_addr;
    void *user_data;
} skcp_msg_t;

inline static skcp_msg_t *skcp_init_msg(u_char type, uint32_t cid, const char *buf, size_t buf_len,
                                        struct sockaddr_in *dst_addr, void *user_data) {
    skcp_msg_t *msg = (skcp_msg_t *)SKCP_ALLOC(sizeof(skcp_msg_t));
    msg->type = type;
    if (dst_addr) {
        msg->dst_addr = *dst_addr;
    }

    if (buf_len > 0 && buf) {
        msg->buf_len = buf_len;
        msg->buf = (char *)SKCP_ALLOC((buf_len));
        memcpy(msg->buf, (buf), (buf_len));
    } else {
        msg->buf = NULL;
        msg->buf_len = 0;
    }
    msg->cid = cid;
    msg->user_data = user_data;
    return msg;
}

#define SKCP_FREE_MSG(_v_msg)               \
    do {                                    \
        if ((_v_msg)) {                     \
            (_v_msg)->buf_len = 0;          \
            if ((_v_msg)->buf) {            \
                SKCP_FREEIF((_v_msg)->buf); \
            }                               \
            SKCP_FREEIF((_v_msg));          \
        }                                   \
    } while (0)

typedef struct skcp_conf_s {
    int mtu;
    int interval;
    int nodelay;
    int resend;
    int nc;
    int sndwnd;
    int rcvwnd;
    int minrto;

    int r_keepalive;  // 单位：秒
    int w_keepalive;  // 单位：秒

    char *addr;
    uint16_t port;
    int r_buf_size;
    int kcp_buf_size;
    int timeout_interval;  // 单位：秒
    uint32_t max_conn_cnt;
    char *key;
    char *ticket;
    int mode;
    uint engine_cnt;
    uint io_cnt;
} skcp_conf_t;

// TODO: fix new iterms
#define SKCP_DEF_CONF(vconf)                     \
    do {                                         \
        memset((vconf), 0, sizeof(skcp_conf_t)); \
        (vconf)->interval = 5;                   \
        (vconf)->mtu = 256;                      \
        (vconf)->rcvwnd = 1024;                  \
        (vconf)->sndwnd = 1024;                  \
        (vconf)->nodelay = 1;                    \
        (vconf)->resend = 2;                     \
        (vconf)->nc = 1;                         \
        (vconf)->minrto = 10;                    \
        (vconf)->r_keepalive = 600;              \
        (vconf)->w_keepalive = 600;              \
        (vconf)->addr = NULL;                    \
        (vconf)->port = 1111;                    \
        (vconf)->r_buf_size = 1500;              \
        (vconf)->kcp_buf_size = 2048;            \
        (vconf)->timeout_interval = 1;           \
        (vconf)->max_conn_cnt = SKCP_MAX_CONNS;  \
        (vconf)->io_cnt = 5;                     \
        (vconf)->engine_cnt = 5;                 \
    } while (0)

/* decode 32 bits unsigned int (lsb) */
inline static const char *skcp_decode32u(const char *p, uint32_t *l) {
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
    *l = *(const unsigned char *)(p + 3);
    *l = *(const unsigned char *)(p + 2) + (*l << 8);
    *l = *(const unsigned char *)(p + 1) + (*l << 8);
    *l = *(const unsigned char *)(p + 0) + (*l << 8);
#else
    memcpy(l, p, 4);
#endif
    p += 4;
    return p;
}

inline static uint64_t skcp_getmillisecond() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

inline static uint32_t skcp_getms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return (uint32_t)(millisecond & 0xfffffffful);
}

inline static uint skcp_route_engine(uint32_t cid, uint engine_cnt) { return cid % engine_cnt; }
inline static uint skcp_route_io(uint32_t cid, uint io_cnt) { return cid % io_cnt; }

inline static void skcp_del_msg(void *data) {
    skcp_msg_t *msg = (skcp_msg_t *)data;
    SKCP_FREE_MSG(msg);
}

// int skcp_io_in_mq_notify_fd[2];
// int skcp_io_out_mq_notify_fd[2];
// int skcp_conn_msg_out_mq_notify_fd[2];

// inline static int skcp_notify_io_in_mq(char c) { return write(skcp_io_in_mq_notify_fd[1], c, 1); }

// inline static int skcp_notify_io_out_mq(char c) { return write(skcp_io_out_mq_notify_fd[1], c, 1); }

#endif  // SKCP_COMMON_H