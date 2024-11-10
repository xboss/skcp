#include "iset.h"

#include <assert.h>
#include <stdio.h>
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
    int num;
    int size;
    struct item_s* prev;
    struct item_s* next;
} item_t;

struct iset_s {
    int capacity;
    item_t** buckets;
    int size;
};

inline static int hash(int num, int cap) {
    return abs(num % cap);
}

static item_t* get(iset_t* s, int num, int* idx) {
    if (!s) return NULL;
    *idx = hash(num, s->capacity);
    item_t* tmp = s->buckets[*idx];
    while (tmp) {
        if (tmp->num == num) {
            return tmp;
        }
        tmp = tmp->next;
    }
    return NULL;
}

iset_t* iset_init(int capacity) {
    iset_t* _ALLOC(s, iset_t*, sizeof(iset_t));
    memset(s, 0, sizeof(iset_t));
    s->capacity = capacity;
    if (s->capacity <= 0) {
        s->capacity = _DEF_CAPACITY;
    }
    _ALLOC(s->buckets, item_t**, sizeof(item_t*) * s->capacity);
    memset(s->buckets, 0, sizeof(item_t*) * s->capacity);
    return s;
}

void iset_free(iset_t* s) {
    if (!s) return;
    if (s->buckets) {
        int i;
        item_t* tmp = NULL;
        for (i = 0; i < s->capacity; i++) {
            while (s->buckets[i]) {
                tmp = s->buckets[i];
                s->buckets[i] = s->buckets[i]->next;
                free(tmp);
            }
        }
        free(s->buckets);
        s->buckets = NULL;
    }
    free(s);
    return;
}

void iset_put(iset_t* s, int num) {
    if (!s) return;
    int idx = -1;
    item_t* tmp = get(s, num, &idx);
    if (tmp) return;
    assert(idx >= 0);
    _ALLOC(tmp, item_t*, sizeof(item_t));
    memset(tmp, 0, sizeof(item_t));
    tmp->next = s->buckets[idx];
    if (s->buckets[idx]) s->buckets[idx]->prev = tmp;
    s->buckets[idx] = tmp;
    s->size++;
    return;
}

void iset_del(iset_t* s, int num) {
    int idx = -1;
    item_t* tmp = get(s, num, &idx);
    if (!tmp) return;
    if (tmp->prev == NULL) {
        assert(idx >= 0);
        free(tmp);
        s->buckets[idx] = NULL;
        s->size--;
        return;
    }
    assert(tmp->prev->next == tmp);
    tmp->prev->next = tmp->next;
    free(tmp);
    s->size--;
    return;
}

int iset_has(iset_t* s, int num) {
    int idx = 0;
    item_t* tmp = get(s, num, &idx);
    if (!tmp) return 0;
    return 1;
}

int iset_size(iset_t* s) {
    if (!s) return 0;
    return s->size;
}

/* test */
/* 
int main(int argc, char const* argv[]) {
    int cnt = 100;
    iset_t* s = iset_init(10);
    int i;
    for (i = 0; i < cnt; i++) {
        iset_put(s, i);
        printf("put i:%d, sz:%d\n", i, iset_size(s));
    }
    i = 1;
    printf("get i:%d, r:%d\n", i, iset_has(s, i));
    i = 100;
    printf("get i:%d, r:%d\n", i, iset_has(s, i));
    i = -1;
    printf("get i:%d, r:%d\n", i, iset_has(s, i));
    i = 23;
    printf("get i:%d, r:%d\n", i, iset_has(s, i));
    for (i = cnt - 1; i >= 50; i--) {
        iset_del(s, i);
        printf("del i:%d, sz:%d\n", i, iset_size(s));
    }
    i = 50;
    printf("get i:%d, r:%d\n", i, iset_has(s, i));
    iset_free(s);
    return 0;
} */
