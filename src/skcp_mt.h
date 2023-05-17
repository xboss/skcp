#ifndef _SKCP_MT_H
#define _SKCP_MT_H

#include <pthread.h>

#include "skcp.h"

/* -------------------------------------------------------------------------- */
/*                                 safe queue                                 */
/* -------------------------------------------------------------------------- */

typedef struct skcp_queue_node_s {
    void *data;
    struct skcp_queue_node_s *next;
    struct skcp_queue_node_s *prev;
} skcp_queue_node_t;

typedef struct {
    skcp_queue_node_t *head;
    skcp_queue_node_t *tail;
    int size;
    int capacity;
    pthread_mutex_t lock;
    pthread_cond_t not_empty_cond;
    pthread_cond_t not_full_cond;
} skcp_queue_t;

/**
 * @param capacity <0: unlimited
 * @return skcp_queue_t*
 */
skcp_queue_t *skcp_init_queue(int capacity);
/**
 * @param q
 * @return full: return 1; not full: return 0;
 */
int skcp_is_queue_full(skcp_queue_t *q);
/**
 * @param q
 * @return empty: return 1; not empty: return 0;
 */
int skcp_is_queue_empty(skcp_queue_t *q);
/**
 * @param q
 * @param data
 * @return int ok:0; error:-1
 */
int skcp_push_queue(skcp_queue_t *q, void *data);
void *skcp_pop_queue(skcp_queue_t *q);
void *skcp_pop_block_queue(skcp_queue_t *q);
void skcp_free_queue(skcp_queue_t *q, void (*fn)(void *data));

/* -------------------------------------------------------------------------- */
/*                                   skcp_mt                                  */
/* -------------------------------------------------------------------------- */

#define SKCP_MSG_T_SEND 1
#define SKCP_MSG_T_CLOSE_CONN 2
#define SKCP_MSG_T_FREE 3
#define SKCP_MSG_T_RECV 4
#define SKCP_MSG_T_ACCEPT 5
#define SKCP_MSG_T_RECV_CID 6
#define SKCP_MSG_T_REQ_CID 7
// #define SKCP_MSG_T_CK_TICKET 8

typedef struct {
    skcp_conf_t *conf;
    struct ev_loop *loop;
    void *user_data;
    SKCP_MODE mode;
    skcp_t *skcp;
    pthread_t skcp_tid;
    skcp_queue_t *in_box;
    skcp_queue_t *out_box;
    ev_async *async_watcher;
    // skcp_queue_t *mq;
    int wait_snd;  // for stat

    void (*notify_fn)();

    // void (*on_accept)(skcp_mt_t *smt, uint32_t cid);
    // void (*on_recv_cid)(skcp_mt_t *smt, uint32_t cid);
    // void (*on_recv_data)(skcp_mt_t *smt, uint32_t cid, char *buf, int len);
    // void (*on_close)(skcp_mt_t *smt, uint32_t cid);
    // int (*on_check_ticket)(skcp_mt_t *smt, char *ticket, int len);
} skcp_mt_t;

typedef struct {
    int type;
    skcp_mt_t *smt;
    uint32_t cid;
    char *buf;
    size_t buf_len;
} skcp_msg_t;

skcp_mt_t *skcp_mt_init(skcp_conf_t *conf, void *user_data, SKCP_MODE mode, void (*notify_fn)());
void skcp_mt_free(skcp_mt_t *smt);
int skcp_mt_send(skcp_mt_t *smt, uint32_t cid, const char *buf, int len);
int skcp_mt_req_cid(skcp_mt_t *smt, const char *ticket, int len);
void skcp_mt_close_conn(skcp_mt_t *smt, uint32_t cid);

#endif