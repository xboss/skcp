#ifndef _SKCP_CONNECTION_H
#define _SKCP_CONNECTION_H

#include <arpa/inet.h>

#include "ikcp.h"
#include "skcp_common.h"
// #include "skcp_engine.h"
#include "skcp_io.h"
#include "skcp_queue.h"

// #define SKCP_CONN_CLOSE_TYPE_TIMEOUT 1
// #define SKCP_CONN_CLOSE_TYPE_MANUAL 2
typedef struct skcp_conn_s skcp_conn_t;

struct skcp_conn_slots_s {
    skcp_conn_t **conns;  // array: id->skcp_conn_t
    uint32_t max_cnt;
    uint32_t remain_cnt;
    uint32_t *remain_id_stack;  // array: remain conn_id stack
    uint32_t remain_idx;
};
typedef struct skcp_conn_slots_s skcp_conn_slots_t;

typedef enum {
    SKCP_CONN_ST_ON = 1,
    SKCP_CONN_ST_OFF,
    // SKCP_CONN_ST_READY,
    // SKCP_CONN_ST_CAN_OFF,
} SKCP_CONN_ST;

// typedef void (*notify_fn_t)(skcp_queue_t *);

// typedef struct skcp_s skcp_t;

typedef struct skcp_engine_s skcp_engine_t;
typedef struct skcp_s skcp_t;

typedef struct skcp_conn_s {
    // skcp_t *skcp;
    uint32_t id;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    // uint64_t estab_tm;
    ikcpcb *kcp;
    SKCP_CONN_ST status;
    // skcp_queue_t *notify_mq;
    // skcp_queue_t *msg_in_mq;

    // skcp_queue_t *msg_out_mq;

    // skcp_queue_t *raw_in_mq;
    // skcp_queue_t *raw_out_mq;
    // int mq_notify_fd[2];
    // char *key;
    // char *ticket;

    struct sockaddr_in dst_addr;

    // struct ev_loop *loop;
    // ev_async *async_watcher;
    // struct ev_timer *kcp_update_watcher;
    // struct ev_timer *timeout_watcher;
    struct ev_timer *tick_watcher;

    skcp_io_t *io;
    skcp_conn_slots_t *conn_slots;
    skcp_conf_t *conf;

    skcp_engine_t *engine;
    skcp_t *skcp;
    // pthread_t tid;
    // void *user_data;
} skcp_conn_t;

skcp_conn_t *skcp_init_conn(skcp_conn_slots_t *conn_slots, skcp_conf_t *conf, uint32_t cid, skcp_io_t **io_list,
                            uint io_cnt);
skcp_conn_t *skcp_get_conn(skcp_conn_slots_t *conn_slots, uint32_t cid);
void skcp_free_conn(skcp_conn_slots_t *conn_slots, uint32_t cid);

/* -------------------------------------------------------------------------- */
/*                              connection slots                              */
/* -------------------------------------------------------------------------- */
skcp_conn_slots_t *skcp_init_conn_slots(uint32_t max_conns);
void skcp_free_conn_slots(skcp_conn_slots_t *slots);
skcp_conn_t *skcp_get_conn_from_slots(skcp_conn_slots_t *slots, uint32_t cid);
uint32_t skcp_borrow_cid_from_slots(skcp_conn_slots_t *slots);
int skcp_return_cid_to_slots(skcp_conn_slots_t *slots, uint32_t cid);
uint32_t skcp_add_new_conn_to_slots(skcp_conn_slots_t *slots, skcp_conn_t *conn);
uint32_t skcp_replace_conn_to_slots(skcp_conn_slots_t *slots, skcp_conn_t *conn);
int skcp_del_conn_from_slots(skcp_conn_slots_t *slots, uint32_t cid);

#endif  // SKCP_CONNECTION_H