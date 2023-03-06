#ifndef _SKCP_H
#define _SKCP_H

#include <arpa/inet.h>
#include <ev.h>

#include "ikcp.h"

/* -------------------------------------------------------------------------- */
/*                                   cipher                                   */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/*                                  protocol                                  */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/*                                    skcp                                    */
/* -------------------------------------------------------------------------- */

#define SKCP_MAX_CONNS 1024
#define SKCP_IV_LEN 32
#define SKCP_KEY_LEN 32
#define SKCP_TICKET_LEN 32

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

typedef enum {
    SKCP_MSG_TYPE_DATA = 1,
    SKCP_MSG_TYPE_CID_ACK,
} SKCP_MSG_TYPE;

typedef struct skcp_s skcp_t;
typedef struct {
    skcp_t *skcp;
    void *user_data;
    uint32_t id;
    IUINT64 last_r_tm;  // 最后一次读操作的时间戳
    IUINT64 last_w_tm;  // 最后一次写操作的时间戳
    IUINT64 estab_tm;
    ikcpcb *kcp;
    SKCP_CONN_ST status;
    // waiting_buf_t *waiting_buf_q;  // 待发送消息的队列头
    struct sockaddr_in dest_addr;
    char ticket[SKCP_TICKET_LEN + 1];
    char iv[SKCP_IV_LEN + 1];
    struct ev_timer *kcp_update_watcher;
    struct ev_timer *timeout_watcher;
} skcp_conn_t;

typedef struct {
    int mtu;
    int interval;
    int nodelay;
    int resend;
    int nc;
    int sndwnd;
    int rcvwnd;

    int estab_timeout;  // 单位：秒
    int r_keepalive;    // 单位：秒
    int w_keepalive;    // 单位：秒

    char *addr;
    uint16_t port;
    char key[SKCP_KEY_LEN + 1];
    int r_buf_size;
    int kcp_buf_size;
    int timeout_interval;  // 单位：秒
    uint32_t max_conn_cnt;
    char ticket[SKCP_TICKET_LEN + 1];

    void (*on_accept)(uint32_t cid);
    void (*on_recv)(uint32_t cid, char *buf, int buf_len, SKCP_MSG_TYPE msg_type);
    void (*on_close)(uint32_t cid);
    int (*on_check_ticket)(char *ticket, int len);
} skcp_conf_t;

typedef struct {
    skcp_conn_t **conns;  // array: id->skcp_conn_t
    uint32_t max_cnt;
    uint32_t remain_cnt;
    uint32_t *remain_id_stack;  // array: remain conn_id stack
    uint32_t remain_idx;
} skcp_conn_slots_t;

struct skcp_s {
    skcp_conf_t *conf;
    skcp_conn_slots_t *conn_slots;
    SKCP_MODE mode;
    int fd;
    struct sockaddr_in servaddr;
    struct ev_loop *loop;
    struct ev_io *r_watcher;
    struct ev_io *w_watcher;
    void *user_data;
    // skcp_fsm *fsm;
};

skcp_t *skcp_init(skcp_conf_t *conf, struct ev_loop *loop, void *user_data, SKCP_MODE mode);
void skcp_free(skcp_t *skcp);
int skcp_req_cid(skcp_t *skcp, const char *ticket, int len);
int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, int len);
void skcp_close_conn(skcp_t *skcp, uint32_t cid);
skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid);

#endif