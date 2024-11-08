#include "iset.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

#define _DEF_CAPACITY 1024

typedef struct item_s {
    int i;
    int size;
    struct item_s *next;
} item_t;

struct iset_s {
    int capacity;
    item_t **buckets;
    int size;
};

inline static int hash(int i, iset_t *set) {
    assert(set);
    return i % set->capacity;
}

iset_t *iset_init(int capacity) {
    iset_t *_ALLOC(set, iset_t *, sizeof(iset_t));
    memset(set, 0, sizeof(iset_t));
    if (capacity <= 0) {
        set->capacity = _DEF_CAPACITY;
    }
    _ALLOC(set->buckets, item_t *, sizeof(item_t *) * set->capacity);
    memset(set->buckets, 0, sizeof(item_t *) * set->capacity);
    return set;
}

void iset_free(iset_t *set) {
    if (!set) return;
    if (set->buckets) {
        int i;
        item_t *item = NULL;
        item_t *tmp = NULL;
        for (i = 0; i < set->capacity; i++) {
            if (!set->buckets) continue;
            item = set->buckets[i];
            while (item) {
                /* TODO: */
            }
        }
        free(set->buckets);
        set->buckets = NULL;
    }
    free(set);
    return;
}

int iset_put(int i) {
    /* TODO: */
    return;
}

int iset_has(int i) {
    /* TODO: */
    return;
}
