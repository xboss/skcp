#ifndef _SKCP_H
#define _SKCP_H

// #include <arpa/inet.h>
// #include <pthread.h>

// #include "ikcp.h"
#include "skcp_connection.h"
#include "skcp_engine.h"
#include "skcp_io.h"
// #include "skcp_threadpool.h"
// #include "skcp_queue.h"

// #define SKCP_IO_MAX 128
// #define SKCP_MAX_CONNS 1024

#define SKCP_IV_LEN 32
#define SKCP_KEY_LEN 32
#define SKCP_TICKET_LEN 32

// #define SKCP_MODE_SERV 1
// #define SKCP_MODE_CLI 2

// #define SKCP_NOTIFY_TYPE_TICK 1
// #define SKCP_NOTIFY_TYPE_ 2

// typedef enum {
//     SKCP_CONN_ST_ON = 1,
//     SKCP_CONN_ST_OFF,
//     // SKCP_CONN_ST_READY,
//     // SKCP_CONN_ST_CAN_OFF,
// } SKCP_CONN_ST;

// typedef void (*notify_fn_t)(skcp_queue_t *);

// typedef struct skcp_s skcp_t;

// typedef struct skcp_conn_s {
//     skcp_t *skcp;
//     uint32_t id;
//     uint64_t last_r_tm;  // 最后一次读操作的时间戳
//     uint64_t last_w_tm;  // 最后一次写操作的时间戳
//     // uint64_t estab_tm;
//     ikcpcb *kcp;
//     SKCP_CONN_ST status;
//     // skcp_queue_t *notify_mq;
//     skcp_queue_t *msg_in_mq;
//     skcp_queue_t *msg_out_mq;
//     // skcp_queue_t *raw_in_mq;
//     // skcp_queue_t *raw_out_mq;
//     // int mq_notify_fd[2];
//     // char *key;
//     // char *ticket;

//     struct sockaddr_in dst_addr;

//     // struct ev_loop *loop;
//     // ev_async *async_watcher;
//     // struct ev_timer *kcp_update_watcher;
//     // struct ev_timer *timeout_watcher;

//     // pthread_t tid;
//     // void *user_data;
// } skcp_conn_t;

// typedef struct {
//     skcp_conn_t **conns;  // array: id->skcp_conn_t
//     uint32_t max_cnt;
//     uint32_t remain_cnt;
//     uint32_t *remain_id_stack;  // array: remain conn_id stack
//     uint32_t remain_idx;
// } skcp_conn_slots_t;
typedef struct skcp_s skcp_t;

typedef void (*on_created_conn_t)(skcp_t *skcp, uint32_t cid);
typedef void (*on_recv_t)(skcp_t *skcp, uint32_t cid, char *buf, int len);
typedef void (*on_close_t)(skcp_t *skcp, uint32_t cid, u_char type);
typedef int (*on_auth_t)(skcp_t *skcp, char *ticket, int len);

typedef struct skcp_s {
    skcp_conf_t *conf;
    skcp_conn_slots_t *conn_slots;
    // int mode;
    skcp_io_t **io_list;
    // uint io_cnt;
    skcp_engine_t **engine_list;
    // uint engine_cnt;
    // notify_fn_t notify_fn;
    // pthread_t tid;
    // skcp_threadpool_t *threadpool;
    skcp_queue_t *in_mq;
    struct ev_loop *loop;
    ev_async *notify_input_watcher;
    // struct ev_io *r_watcher;

    // struct ev_io *r_notify_watcher;
    // struct ev_timer *tick_watcher;
    on_created_conn_t on_created_conn;
    on_recv_t on_recv;
    on_close_t on_close;
    on_auth_t on_auth;

    void *user_data;

} skcp_t;

skcp_t *skcp_init(skcp_conf_t *conf, struct ev_loop *loop, on_created_conn_t on_created_conn, on_recv_t on_recv,
                  on_close_t on_close, on_auth_t on_auth, void *user_data);
void skcp_free(skcp_t *skcp);
int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, size_t len);
int skcp_req_cid(skcp_t *skcp, const char *ticket, int len);

uint32_t skcp_create_conn(skcp_t *skcp);
void skcp_close_conn(skcp_t *skcp, uint32_t cid);

// skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid);

#endif