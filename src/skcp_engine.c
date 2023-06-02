#include "skcp_engine.h"

#include <ev.h>

#include "stddef.h"

static int kcp_output(const char *buf, int len, struct IKCPCB *kcp, void *user) {
    skcp_conn_t *conn = (skcp_conn_t *)user;

    // // 加密
    // char *cipher_buf = NULL;
    // int cipher_buf_len = 0;
    // if (strlen(conn->skcp->conf->key) > 0) {
    //     cipher_buf = aes_encrypt(conn->skcp->conf->key, def_iv, buf, len, &cipher_buf_len);
    // }

    // int rt = skcp_io_send(conn->skcp->io, cipher_buf, cipher_buf_len, conn->dst_addr);
    // _FREEIF(cipher_buf);
    int rt = skcp_io_send(conn->io, buf, len, conn->dst_addr);
    if (rt > 0) {
        conn->last_w_tm = skcp_getmillisecond();
    }

    return rt;
}

static void tick_cb(struct ev_loop *loop, ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        // _LOG("kcp update got invalid event");
        return;
    }
    skcp_conn_t *conn = (skcp_conn_t *)(watcher->data);
    // SKCP_LOG("engine tick_cb %u", conn->id);

    if (conn->status == SKCP_CONN_ST_OFF) {
        SKCP_LOG("engine tick_cb real close %u", conn->id);
        ev_timer_stop(loop, watcher);
        skcp_free_conn(conn->conn_slots, conn->id);
        return;
    }

    ikcp_update(conn->kcp, skcp_getms());  // clock()

    // check timeout
    uint64_t now = skcp_getmillisecond();
    if (now - conn->last_r_tm > conn->conf->r_keepalive * 1000) {
        SKCP_LOG("engine tick_cb timeout %u", conn->id);
        skcp_msg_t *msg = skcp_init_msg(SKCP_MSG_TYPE_CLOSE_TIMEOUT, conn->id, NULL, 0, NULL, conn->skcp);
        // SKCP_INIT_ENGINE_MSG(msg, SKCP_MSG_TYPE_CLOSE_TIMEOUT, conn->id, NULL, 0, conn->skcp);
        conn->engine->handler(msg);
        SKCP_FREE_MSG(msg);
        skcp_free_conn(conn->conn_slots, conn->id);
        conn = NULL;
    }

    // TODO:  for test
    if (conn) {
        uint64_t t = now % 1000;
        int waitsnd = ikcp_waitsnd(conn->kcp);
        if (t > 0 && t < 20 && waitsnd > 10) {
            SKCP_LOG(">>> waitsnd: %d", waitsnd);
        }
    }
}

static void *routine_fn(void *arg) {
    skcp_engine_t *engine = (skcp_engine_t *)arg;
    // SKCP_LOG("start engine thread start running ok %d %lld", engine->id, pthread_self());
    SKCP_LOG("start engine thread start running ok %d", engine->id);
    ev_run(engine->loop, 0);
    SKCP_LOG("start engine thread end running ok %d", engine->id);
    return NULL;
}

static int on_msg_input(skcp_engine_t *engine, skcp_msg_t *msg) {
    skcp_conn_t *conn = skcp_get_conn(engine->conn_slots, msg->cid);

    if (!conn || conn->status != SKCP_CONN_ST_ON) {
        return SKCP_ERR;
    }

    ikcp_input(conn->kcp, msg->buf, msg->buf_len);

    ikcp_update(conn->kcp, skcp_getms());
    char *kcp_recv_buf = (char *)SKCP_ALLOC(engine->conf->kcp_buf_size);
    int recv_len = ikcp_recv(conn->kcp, kcp_recv_buf, engine->conf->kcp_buf_size);
    ikcp_update(conn->kcp, skcp_getms());
    if (recv_len < 0) {
        // TODO: 返回-1表示数据还没有收完数据，-3表示接受buf太小
        if (recv_len == -3) {
            SKCP_LOG("ikcp_recv error %d cid: %u", recv_len, conn->id);
        }
        SKCP_FREEIF(kcp_recv_buf);
        return SKCP_ERR;
    }
    // ok
    skcp_msg_t *recv_msg = skcp_init_msg(SKCP_MSG_TYPE_RECV, msg->cid, kcp_recv_buf, recv_len, NULL, engine->user_data);
    // SKCP_INIT_ENGINE_MSG(recv_msg, SKCP_MSG_TYPE_RECV, msg->cid, kcp_recv_buf, recv_len, engine->user_data);
    SKCP_FREEIF(kcp_recv_buf);
    engine->handler(recv_msg);
    SKCP_FREE_MSG(recv_msg);
    conn->last_r_tm = skcp_getmillisecond();

    return SKCP_OK;
}

static int on_msg_send(skcp_engine_t *engine, skcp_msg_t *msg) {
    skcp_conn_t *conn = skcp_get_conn(engine->conn_slots, msg->cid);

    if (!conn || conn->status != SKCP_CONN_ST_ON) {
        return SKCP_ERR;
    }

    if (ikcp_send(conn->kcp, msg->buf, msg->buf_len) < 0) {
        SKCP_LOG("ikcp_send error cid: %u", conn->id);
        return SKCP_ERR;
    }
    ikcp_update(conn->kcp, skcp_getms());
    ikcp_flush(conn->kcp);  // TODO:

    return SKCP_OK;
}

static int on_msg_close(skcp_engine_t *engine, skcp_msg_t *msg) {
    // skcp_free_conn(engine->conn_slots, msg->cid);
    skcp_conn_t *conn = skcp_get_conn(engine->conn_slots, msg->cid);
    conn->status = SKCP_CONN_ST_OFF;
    engine->handler(msg);
    return SKCP_OK;
}

static void notify_input_cb(struct ev_loop *loop, struct ev_async *watcher, int revents) {
    skcp_engine_t *engine = (skcp_engine_t *)watcher->data;
    // SKCP_LOG("engine notify_input_cb %d", engine->id);

    // send
    while (engine->in_mq->size > 0) {
        skcp_msg_t *msg = (skcp_msg_t *)skcp_pop_queue(engine->in_mq);
        // if (!msg) {
        //     continue;
        // }
        if (msg->type == SKCP_MSG_TYPE_INPUT) {
            on_msg_input(engine, msg);
        } else if (msg->type == SKCP_MSG_TYPE_SEND) {
            on_msg_send(engine, msg);
        } else if (msg->type == SKCP_MSG_TYPE_CLOSE_TIMEOUT || msg->type == SKCP_MSG_TYPE_CLOSE_MANUAL) {
            on_msg_close(engine, msg);
        } else {
            SKCP_LOG("error msg type %x", msg->type);
        }
        SKCP_FREE_MSG(msg);
    }
}

skcp_engine_t *skcp_engine_init(int id, skcp_conn_slots_t *conn_slots, skcp_conf_t *conf, void (*handler)(skcp_msg_t *),
                                void *user_data) {
    if (id < 0 || !conn_slots || !conf) {
        return NULL;
    }

    skcp_engine_t *engine = (skcp_engine_t *)SKCP_ALLOC(sizeof(skcp_engine_t));
    engine->id = id;
    // engine->tick_interval = tick_interval;
    engine->handler = handler;
    engine->conn_slots = conn_slots;
    engine->conf = conf;
    engine->user_data = user_data;
    engine->in_mq = skcp_init_queue(-1);
    if (!engine->in_mq) {
        skcp_engine_free(engine);
        return NULL;
    }

#if (defined(__linux__) || defined(__linux))
    engine->loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    engine->loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    engine->loop = ev_default_loop(0);
#endif

    engine->notify_input_watcher = (ev_async *)SKCP_ALLOC(sizeof(ev_async));
    engine->notify_input_watcher->data = engine;
    ev_async_init(engine->notify_input_watcher, notify_input_cb);
    ev_async_start(engine->loop, engine->notify_input_watcher);

    if (pthread_create(&engine->tid, NULL, routine_fn, engine)) {  // TODO:  free it
        SKCP_LOG("start engine thread error %d", engine->id);
        skcp_engine_free(engine);
        return NULL;
    }

    SKCP_LOG("start engine thread ok %d", engine->id);

    return engine;
}

void skcp_engine_free(skcp_engine_t *engine) {
    if (!engine) {
        return;
    }

    if (engine->loop) {
        // TODO: 可能需要feed event 和 free watcher
        ev_break(engine->loop, EVBREAK_ALL);
        ev_loop_destroy(engine->loop);
    }

    if (engine->in_mq) {
        skcp_free_queue(engine->in_mq, skcp_del_msg);
        engine->in_mq = NULL;
    }

    SKCP_FREEIF(engine);
}

int skcp_engine_reg_conn(skcp_engine_t *engine, skcp_conn_t *conn) {
    conn->engine = engine;
    conn->kcp->output = kcp_output;
    conn->tick_watcher->data = conn;
    ev_init(conn->tick_watcher, tick_cb);
    ev_timer_set(conn->tick_watcher, 0, engine->conf->interval / 1000.0);
    ev_timer_start(engine->loop, conn->tick_watcher);
    return SKCP_OK;
}

// 驱动engine的运行，feed各种类型的消息，包含：业务曾需要发送的消息，conn的状态变化消息，来自io层的消息
int skcp_engine_feed(skcp_engine_t *engine, skcp_msg_t *msg) {
    if (!engine || !msg) {
        return SKCP_ERR;
    }
    if (skcp_push_queue(engine->in_mq, msg) != 0) {
        return SKCP_ERR;
    }
    ev_async_send(engine->loop, engine->notify_input_watcher);

    return SKCP_OK;
}