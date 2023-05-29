#ifndef _SKCP_ENGINE_H
#define _SKCP_ENGINE_H

#include <pthread.h>

#include "skcp_common.h"
#include "skcp_connection.h"
#include "skcp_queue.h"

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