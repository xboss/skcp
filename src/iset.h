#ifndef _ISET_H
#define _ISET_H

typedef struct iset_s iset_t;

iset_t *iset_init(int capacity);
void iset_free(iset_t *set);
int iset_put(int i);
int iset_has(int i);

#endif /* ISET_H */