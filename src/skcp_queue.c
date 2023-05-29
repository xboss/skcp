#include "skcp_queue.h"

#include <stddef.h>

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
    //     SKCP_FREEIF(q);
    //     SKCP_LOG("init lock error in skcp_init_queue");
    //     return NULL;
    // }
    if (pthread_mutex_init(&q->lock, NULL) != 0 || pthread_cond_init(&q->not_empty_cond, NULL) != 0 ||
        pthread_cond_init(&q->not_full_cond, NULL) != 0) {
        SKCP_FREEIF(q);
        SKCP_LOG("init lock or cond error in skcp_init_block_queue");
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
        SKCP_LOG("safe queue is full");
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
    SKCP_FREEIF(node);
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
    SKCP_FREEIF(node);
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
    SKCP_FREEIF(q);
}