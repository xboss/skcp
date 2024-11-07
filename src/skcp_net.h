#ifndef _SKCP_NET_H
#define _SKCP_NET_H

#include <ev.h>

#include "skcp.h"

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)

typedef enum { SKCP_NET_CHAN_TCP = 1, SKCP_NET_CHAN_KCP, SKCP_NET_CHAN_UDP } SKCP_NET_CHANNEL_T;

/* struct skcp_net_s {
    skcp_t* skcp;
    struct ev_loop* loop;
    char* rcv_buf;
};
typedef struct skcp_net_s skcp_net_t; */

int skcp_init_udp(int is_bind);
/* int skcp_init_tcp_server(); */
int skcp_net_send();

int skcp_net_set_reuseaddr(int fd);
int skcp_net_set_nonblocking(int fd);

#endif /* SKCP_NET_H */
