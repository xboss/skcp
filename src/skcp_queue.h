#ifndef _SKCP_QUEUE_H
#define _SKCP_QUEUE_H

#include <pthread.h>

#include "skcp_common.h"

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

#endif  // SKCP_QUEUE_H