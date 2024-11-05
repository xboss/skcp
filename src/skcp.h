#ifndef _SKCP_H
#define _SKCP_H

#include <arpa/inet.h>

#include "ikcp.h"
#include "uthash.h"

/* #define SKCP_MAX_RW_BUF_LEN 1500 */
#define SKCP_CIPHER_KEY_LEN 16
#if !defined(INET_ADDRSTRLEN)
#define INET_ADDRSTRLEN 16
#endif  // INET_ADDRSTRLEN

typedef enum { SKCP_CONN_ST_ON = 1, SKCP_CONN_ST_OFF } SKCP_CONN_ST;
typedef enum { SKCP_MODE_SERV = 1, SKCP_MODE_CLI } SKCP_MODE;

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

    SKCP_MODE mode;
    /* int is_secret; */
    int r_keepalive; /* seconds */
    int w_keepalive; /* seconds */

    char addr[INET_ADDRSTRLEN + 1];
    uint16_t port;
    char key[SKCP_CIPHER_KEY_LEN + 1];

    int (*skcp_output_cb)(skcp_t *skcp, uint32_t cid, const char *buf, int len);
    /*     void (*on_update)(skcp_t *skcp, uint32_t cid);
        void (*on_recv_data)(skcp_t *skcp, uint32_t cid, char *buf, int len);
        void (*on_close)(skcp_t *skcp, uint32_t cid); */
} skcp_conf_t;

struct skcp_conn_s {
    uint32_t id;
    skcp_t *skcp;
    /* void *user_data; */
    /*     uint64_t last_r_tm;
        uint64_t last_w_tm;
        uint64_t estab_tm; */
    ikcpcb *kcp;
    SKCP_CONN_ST status;
    /* struct sockaddr_in target_addr; */
    void *ud;
    UT_hash_handle hh;
};

struct skcp_s {
    int fd;
    skcp_conf_t conf;
    skcp_conn_t *conn_tb;
    struct sockaddr_in servaddr;
    char *cipher_buf;
    void *user_data;
};

/* #define SKCP_DEF_CONF(vconf)                     \
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
    } while (0) */

skcp_t *skcp_init(int fd, skcp_conf_t *conf, void *user_data);
void skcp_free(skcp_t *skcp);
int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, int len);
void skcp_close_conn(skcp_t *skcp, uint32_t cid);
skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid);
void skcp_update(skcp_t *skcp, uint32_t cid);
int skcp_input(skcp_t *skcp, uint32_t cid, const char *buf, int len);

#endif