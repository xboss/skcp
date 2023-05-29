#ifndef _SKCP_ENGINE_H
#define _SKCP_ENGINE_H

#include <pthread.h>

#include "skcp_common.h"
#include "skcp_connection.h"
#include "skcp_queue.h"

// #define SKCP_ENGINE_MSG_TYPE_INPUT 0x1
// #define SKCP_ENGINE_MSG_TYPE_SEND 0x2
// #define SKCP_ENGINE_MSG_TYPE_RECV 0x3
// #define SKCP_ENGINE_MSG_TYPE_CLOSE 0x4

// #define SKCP_ENGINE_INIT_MSG(_v_msg, _v_type, _v_cid, _v_buf, _v_buf_len, _v_user_data)           \
//     do {                                                                                          \
//         skcp_engine_msg_t *(_v_msg) = (skcp_engine_msg_t *)SKCP_ALLOC(sizeof(skcp_engine_msg_t)); \
//         (_v_msg)->type = (_v_type);                                                               \
//         (_v_msg)->cid = (_v_cid);                                                                 \
//         (_v_msg)->buf_len = (_v_buf_len);                                                         \
//         (_v_msg)->buf = (char *)SKCP_ALLOC((_v_buf_len));                                         \
//         memcpy((_v_msg)->buf, (_v_buf), (_v_buf_len));                                            \
//         (_v_msg)->user_data = (_v_user_data);                                                     \
//     } while (0)

// #define SKCP_ENGINE_FREE_MSG(_v_msg)        \
//     do {                                    \
//         if ((_v_msg)) {                     \
//             (_v_msg)->buf_len = 0;          \
//             if ((_v_msg)->buf) {            \
//                 SKCP_FREEIF((_v_msg)->buf); \
//             }                               \
//             SKCP_FREEIF((_v_msg));          \
//         }                                   \
//     } while (0)

// typedef struct {
//     u_char type;
//     uint32_t cid;
//     char *buf;
//     size_t buf_len;
//     void *user_data;
//     // skcp_conn_t *conn;
// } skcp_engine_msg_t;

typedef struct skcp_engine_s {
    int id;
    pthread_t tid;
    // int tick_interval;
    struct ev_loop *loop;
    ev_async *notify_input_watcher;
    // struct ev_timer *tick_watcher;
    skcp_queue_t *in_mq;
    skcp_conn_slots_t *conn_slots;
    skcp_conf_t *conf;
    void *user_data;

    void (*handler)(skcp_msg_t *);
} skcp_engine_t;

skcp_engine_t *skcp_engine_init(int id, skcp_conn_slots_t *conn_slots, skcp_conf_t *conf, void (*handler)(skcp_msg_t *),
                                void *user_data);
void skcp_engine_free(skcp_engine_t *engine);
int skcp_engine_reg_conn(skcp_engine_t *engine, skcp_conn_t *conn);
// 驱动engine的运行，feed各种类型的消息，包含：业务曾需要发送的消息，conn的状态变化消息，来自io层的消息
int skcp_engine_feed(skcp_engine_t *engine, skcp_msg_t *msg);

// void skcp_engine_notify();
// void skcp_engine_feed(skcp_engine_msg_t *msg);

#endif  // SKCP_ENGINE_H