#include "skcp_mt.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define _ALLOC(element_size) calloc(1, element_size)

#define _FREEIF(p)    \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0)

#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)

/* -------------------------------------------------------------------------- */
/*                                 safe queue                                 */
/* -------------------------------------------------------------------------- */

/**
 * @param capacity <0: unlimited
 * @return skcp_queue_t*
 */
skcp_queue_t *skcp_init_queue(int capacity) {
    skcp_queue_t *q = (skcp_queue_t *)calloc(1, sizeof(skcp_queue_t));
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    q->capacity = capacity;
    // if (pthread_mutex_init(&q->lock, NULL) != 0) {
    //     _FREEIF(q);
    //     _LOG("init lock error in skcp_init_queue");
    //     return NULL;
    // }
    if (pthread_mutex_init(&q->lock, NULL) != 0 || pthread_cond_init(&q->not_empty_cond, NULL) != 0 ||
        pthread_cond_init(&q->not_full_cond, NULL) != 0) {
        _FREEIF(q);
        _LOG("init lock or cond error in skcp_init_block_queue");
        return NULL;
    }
    return q;
}

/**
 * @param q
 * @return full: return 1; not full: return 0;
 */
int skcp_is_queue_full(skcp_queue_t *q) {
    if (q->capacity < 0) {
        return 0;
    }

    if (q->size >= q->capacity) {
        return 1;
    }
    return 0;
}

/**
 * @param q
 * @return empty: return 1; not empty: return 0;
 */
int skcp_is_queue_empty(skcp_queue_t *q) {
    if (q->size == 0) {
        return 1;
    }
    return 0;
}

/**
 * @param q
 * @param data
 * @return int ok:0; error:-1
 */
int skcp_push_queue(skcp_queue_t *q, void *data) {
    // LOG_I("skcp_push_queue size: %d", q->size);
    if (skcp_is_queue_full(q)) {
        _LOG("safe queue is full");
        return -1;
    }

    pthread_mutex_lock(&q->lock);
    skcp_queue_node_t *node = (skcp_queue_node_t *)calloc(1, sizeof(skcp_queue_node_t));
    node->data = data;
    node->prev = NULL;
    node->next = NULL;
    if (skcp_is_queue_empty(q)) {
        q->head = node;
        q->tail = node;
    } else {
        node->next = q->head;
        q->head->prev = node;
        q->head = node;
    }
    q->size++;
    pthread_cond_signal(&q->not_empty_cond);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

void *skcp_pop_queue(skcp_queue_t *q) {
    // LOG_I("skcp_pop_queue size: %d", q->size);
    if (skcp_is_queue_empty(q)) {
        return NULL;
    }

    pthread_mutex_lock(&q->lock);
    skcp_queue_node_t *node = q->tail;
    if (q->size == 1) {
        // 只有一个节点
        q->tail = NULL;
        q->head = NULL;
    } else {
        // 多个节点
        q->tail->prev->next = NULL;
        q->tail = q->tail->prev;
    }

    q->size--;
    void *data = node->data;
    _FREEIF(node);
    pthread_mutex_unlock(&q->lock);
    return data;
}

void *skcp_pop_block_queue(skcp_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    if (skcp_is_queue_empty(q)) {
        pthread_cond_wait(&q->not_empty_cond, &q->lock);
    }
    // LOG_I("skcp_pop_block_queue size: %d", q->size);
    skcp_queue_node_t *node = q->tail;
    if (q->size == 1) {
        // 只有一个节点
        q->tail = NULL;
        q->head = NULL;
    } else {
        // 多个节点
        q->tail->prev->next = NULL;
        q->tail = q->tail->prev;
    }

    q->size--;
    void *data = node->data;
    _FREEIF(node);
    pthread_mutex_unlock(&q->lock);
    return data;
}

void skcp_free_queue(skcp_queue_t *q, void (*fn)(void *data)) {
    if (!q) {
        return;
    }
    while (q->size > 0) {
        void *data = skcp_pop_queue(q);
        if (fn) {
            fn(data);
        }
    }
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty_cond);
    pthread_cond_destroy(&q->not_full_cond);
    q->size = q->capacity = 0;
    _FREEIF(q);
}

/* -------------------------------------------------------------------------- */
/*                                   common                                   */
/* -------------------------------------------------------------------------- */

inline static uint64_t getmillisecond() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

/* -------------------------------------------------------------------------- */
/*                                 private api                                */
/* -------------------------------------------------------------------------- */
static void free_msg(void *data) {
    if (!data) {
        return;
    }
    skcp_msg_t *msg = (skcp_msg_t *)data;
    _FREEIF(msg->buf);
    _FREEIF(msg);
}

static void free_smt(skcp_mt_t *smt) {
    if (!smt) {
        return;
    }

    if (smt->async_watcher) {
        ev_loop_destroy(smt->loop);
        smt->loop = NULL;
        _FREEIF(smt->async_watcher);
    }

    if (smt->skcp) {
        skcp_free(smt->skcp);
    }

    if (smt->in_box) {
        skcp_free_queue(smt->in_box, free_msg);
        smt->in_box = NULL;
    }

    if (smt->out_box) {
        skcp_free_queue(smt->out_box, free_msg);
        smt->out_box = NULL;
    }

    _FREEIF(smt);
}

/* -------------------------------------------------------------------------- */
/*                                  callback                                  */
/* -------------------------------------------------------------------------- */
static void on_accept(skcp_t *skcp, uint32_t cid) {
    skcp_mt_t *smt = (skcp_mt_t *)skcp->user_data;
    skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    msg->type = SKCP_MSG_T_ACCEPT;
    msg->smt = smt;
    msg->cid = cid;
    if (skcp_push_queue(smt->out_box, msg) == 0) {
        smt->notify_fn();
    }
}
static void on_recv_cid(skcp_t *skcp, uint32_t cid) {
    skcp_mt_t *smt = (skcp_mt_t *)skcp->user_data;
    skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    msg->type = SKCP_MSG_T_RECV_CID;
    msg->smt = smt;
    msg->cid = cid;
    if (skcp_push_queue(smt->out_box, msg) == 0) {
        smt->notify_fn();
    }
}
static void on_recv_data(skcp_t *skcp, uint32_t cid, char *buf, int len) {
    skcp_mt_t *smt = (skcp_mt_t *)skcp->user_data;
    skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    msg->type = SKCP_MSG_T_RECV;
    msg->smt = smt;
    msg->cid = cid;
    msg->buf = (char *)calloc(1, len);
    memcpy(msg->buf, buf, len);
    msg->buf_len = len;
    if (skcp_push_queue(smt->out_box, msg) == 0) {
        smt->notify_fn();
    }
}
static void on_close(skcp_t *skcp, uint32_t cid) {
    skcp_mt_t *smt = (skcp_mt_t *)skcp->user_data;
    skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    msg->type = SKCP_MSG_T_CLOSE_CONN;
    msg->smt = smt;
    msg->cid = cid;
    if (skcp_push_queue(smt->out_box, msg) == 0) {
        smt->notify_fn();
    }
}
static int on_check_ticket(skcp_t *skcp, char *ticket, int len) {
    // skcp_mt_t *smt = (skcp_mt_t *)skcp->user_data;
    // skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    // msg->type = SKCP_MSG_T_CK_TICKET;
    // msg->smt = smt;
    // msg->buf = (char *)calloc(1, len);
    // memcpy(msg->buf, ticket, len);
    // msg->buf_len = len;
    // if (skcp_push_queue(smt->out_box, msg) == 0) {
    //     smt->notify_fn();
    // }

    // TODO: 同步返回
    return 0;
}

static void async_cb(struct ev_loop *loop, ev_async *watcher, int revents) {
    // _LOG("async_cb...");
    skcp_mt_t *smt = (skcp_mt_t *)watcher->data;
    while (smt->in_box->size > 0) {
        skcp_msg_t *msg = (skcp_msg_t *)skcp_pop_queue(smt->in_box);
        if (msg->type == SKCP_MSG_T_SEND) {
            if (skcp_send(msg->smt->skcp, msg->cid, msg->buf, msg->buf_len) < 0) {
                _LOG("async_cb skcp_send error cid: %u", msg->cid);
                // TODO: 按顺序放回队列
            }
        } else if (msg->type == SKCP_MSG_T_CLOSE_CONN) {
            skcp_close_conn(msg->smt->skcp, msg->cid);
        } else if (msg->type == SKCP_MSG_T_FREE) {
            free_smt(smt);
        } else if (msg->type == SKCP_MSG_T_REQ_CID) {
            if (skcp_req_cid(msg->smt->skcp, msg->buf, msg->buf_len) < 0) {
                _LOG("async_cb skcp_req_cid error");
                // TODO: 按顺序放回队列
            }
        } else {
            _LOG("error msg type in async_cb");
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                 public api                                 */
/* -------------------------------------------------------------------------- */

static void *thread_fn(void *arg) {
    // sleep(1);
    skcp_mt_t *smt = (skcp_mt_t *)arg;

    smt->conf->on_accept = on_accept;
    smt->conf->on_check_ticket = on_check_ticket;
    smt->conf->on_close = on_close;
    smt->conf->on_recv_cid = on_recv_cid;
    smt->conf->on_recv_data = on_recv_data;

    smt->loop = NULL;
#if (defined(__linux__) || defined(__linux))
    smt->loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    smt->loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    smt->loop = ev_default_loop(0);
#endif

    smt->skcp = skcp_init(smt->conf, smt->loop, smt, smt->mode);
    if (!smt->skcp) {
        _LOG("init skcp error");
        return NULL;
    }

    smt->async_watcher = (ev_async *)calloc(1, sizeof(ev_async));
    smt->async_watcher->data = smt;
    ev_async_init(smt->async_watcher, async_cb);
    ev_async_start(smt->loop, smt->async_watcher);

    ev_run(smt->loop, 0);

    return NULL;
}

skcp_mt_t *skcp_mt_init(skcp_conf_t *conf, void *user_data, SKCP_MODE mode, void (*notify_fn)()) {
    if (!conf) {
        return NULL;
    }

    skcp_mt_t *smt = (skcp_mt_t *)_ALLOC(sizeof(skcp_mt_t));
    smt->notify_fn = notify_fn;
    smt->conf = conf;
    smt->mode = mode;
    smt->user_data = user_data;
    // smt->on_accept = conf->on_accept;
    // smt->on_check_ticket = conf->on_check_ticket;
    // smt->on_close = conf->on_close;
    // smt->on_recv_cid = conf->on_recv_cid;
    // smt->on_recv_data = conf->on_recv_data;
    smt->in_box = skcp_init_queue(-1);
    smt->out_box = skcp_init_queue(-1);

    if (pthread_create(&smt->skcp_tid, NULL, thread_fn, smt)) {
        _LOG("start skcp thread error");
        skcp_free_queue(smt->in_box, NULL);
        smt->in_box = NULL;
        skcp_free_queue(smt->out_box, NULL);
        smt->out_box = NULL;
        _FREEIF(smt);
        return NULL;
    }

    return smt;
}

void skcp_mt_free(skcp_mt_t *smt) {
    skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    msg->type = SKCP_MSG_T_FREE;
    msg->smt = smt;
    if (skcp_push_queue(smt->in_box, msg) == 0) {
        ev_async_send(smt->loop, smt->async_watcher);
    }
}

int skcp_mt_send(skcp_mt_t *smt, uint32_t cid, const char *buf, int len) {
    skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    msg->type = SKCP_MSG_T_SEND;
    msg->smt = smt;
    msg->cid = cid;
    msg->buf = (char *)calloc(1, len);
    memcpy(msg->buf, buf, len);
    msg->buf_len = len;
    if (skcp_push_queue(smt->in_box, msg) == 0) {
        skcp_conn_t *conn = skcp_get_conn(smt->skcp, cid);
        if (conn) {
            smt->wait_snd = ikcp_waitsnd(conn->kcp);
            // if (wait_snd < conn->kcp->snd_wnd) {
            if (smt->wait_snd < 200) {
                ev_async_send(smt->loop, smt->async_watcher);
            }
            // else {
            //     if (wait_snd % 10 == 1) {  // TODO: for test
            //         _LOG("stop send notify wait_snd: %d", wait_snd);
            //     }
            // }
        }
    }
    return len;
}

int skcp_mt_req_cid(skcp_mt_t *smt, const char *ticket, int len) {
    skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    msg->type = SKCP_MSG_T_REQ_CID;
    msg->smt = smt;
    msg->buf = (char *)calloc(1, len);
    memcpy(msg->buf, ticket, len);
    msg->buf_len = len;
    if (skcp_push_queue(smt->in_box, msg) == 0) {
        ev_async_send(smt->loop, smt->async_watcher);
    }
    return len;
}

void skcp_mt_close_conn(skcp_mt_t *smt, uint32_t cid) {
    skcp_msg_t *msg = (skcp_msg_t *)calloc(1, sizeof(skcp_msg_t));
    msg->type = SKCP_MSG_T_CLOSE_CONN;
    msg->smt = smt;
    msg->cid = cid;
    if (skcp_push_queue(smt->in_box, msg) == 0) {
        ev_async_send(smt->loop, smt->async_watcher);
    }
}
