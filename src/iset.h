#ifndef _ISET_H
#define _ISET_H

typedef struct iset_s iset_t;

iset_t *iset_init(int capacity);
void iset_free(iset_t *set);
void iset_put(iset_t* s, int num);
void iset_del(iset_t* s, int num);
int iset_has(iset_t* s, int num);
int iset_size(iset_t* s);


#endif /* ISET_H */