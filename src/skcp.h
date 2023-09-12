#ifndef _SKCP_H
#define _SKCP_H

#include <arpa/inet.h>
#include <ev.h>

#include "ikcp.h"
#include "uthash.h"

#define SKCP_IV_LEN 32
#define SKCP_KEY_LEN 32
#define SKCP_TICKET_LEN 32
#define SKCP_MAX_RW_BUF_LEN 1500

typedef enum {
    SKCP_CONN_ST_ON = 1,
    SKCP_CONN_ST_OFF,
    // SKCP_CONN_ST_READY,
    // SKCP_CONN_ST_CAN_OFF,
} SKCP_CONN_ST;

typedef enum {
    SKCP_MODE_SERV = 1,
    SKCP_MODE_CLI,
} SKCP_MODE;

typedef struct skcp_conn_s skcp_conn_t;
typedef struct skcp_s skcp_t;

typedef struct skcp_conf_s {
    int mtu;
    int interval;
    int nodelay;
    int resend;
    int nc;
    int sndwnd;
    int rcvwnd;

    int r_keepalive;  // 单位：秒
    int w_keepalive;  // 单位：秒

    char *addr;
    uint16_t port;
    uint32_t max_conn_cnt;
    char key[SKCP_KEY_LEN + 1];
    char ticket[SKCP_TICKET_LEN + 1];

    void (*on_accept)(skcp_t *skcp, uint32_t cid);
    void (*on_recv_cid)(skcp_t *skcp, uint32_t cid);
    void (*on_recv_data)(skcp_t *skcp, uint32_t cid, char *buf, int len);
    void (*on_close)(skcp_t *skcp, uint32_t cid);
    int (*on_check_ticket)(skcp_t *skcp, char *ticket, int len);
} skcp_conf_t;

struct skcp_conn_s {
    skcp_t *skcp;
    void *user_data;
    uint32_t id;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    uint64_t estab_tm;
    ikcpcb *kcp;
    SKCP_CONN_ST status;
    struct sockaddr_in target_addr;
    char ticket[SKCP_TICKET_LEN + 1];
    struct ev_timer *kcp_update_watcher;
    UT_hash_handle hh;
};

struct skcp_s {
    skcp_conf_t *conf;
    skcp_conn_t *conns;
    char *key;
    SKCP_MODE mode;
    int fd;
    struct sockaddr_in servaddr;
    struct ev_loop *loop;
    struct ev_io *r_watcher;
    void *user_data;
    uint32_t cid_seed;
};

#define SKCP_DEF_CONF(vconf)                     \
    do {                                         \
        memset((vconf), 0, sizeof(skcp_conf_t)); \
        (vconf)->interval = 5;                   \
        (vconf)->mtu = 1424;                     \
        (vconf)->rcvwnd = 1024;                  \
        (vconf)->sndwnd = 1024;                  \
        (vconf)->nodelay = 1;                    \
        (vconf)->resend = 2;                     \
        (vconf)->nc = 1;                         \
        (vconf)->r_keepalive = 600;              \
        (vconf)->w_keepalive = 600;              \
        (vconf)->addr = NULL;                    \
        (vconf)->port = 1111;                    \
        (vconf)->max_conn_cnt = SKCP_MAX_CONNS;  \
    } while (0)

skcp_t *skcp_init(skcp_conf_t *conf, struct ev_loop *loop, void *user_data, SKCP_MODE mode);
void skcp_free(skcp_t *skcp);
int skcp_req_cid(skcp_t *skcp, const char *ticket, int len);
int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, int len);
void skcp_close_conn(skcp_t *skcp, uint32_t cid);
skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid);

#endif