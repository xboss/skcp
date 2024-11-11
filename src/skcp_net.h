#ifndef _SKCP_NET_H
#define _SKCP_NET_H

#include <arpa/inet.h>
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

/* cmd(1B)|ticket_id(4B) */
#define SKCP_NET_UDP_HEAD_LEN 5

#define SKCP_NET_CMD_KCP 'k'
#define SKCP_NET_CMD_PING 'i'
#define SKCP_NET_CMD_PONG 'o'

#define SKCP_NET_BASE_FIELDS         \
    skcp_t* skcp;                    \
    struct ev_loop* loop;            \
    char* rcv_buf;                   \
    int udp_fd;                      \
    int rw_buf_size;                 \
    struct sockaddr_in udp_sockaddr; \
    skcp_rcv_cb_t skcp_rcv_cb

struct skcp_udp_conn_s {
    int fd;
    uint32_t cid;
    int ticket_id;
    struct sockaddr_in target_sockaddr;
    struct ev_timer* update_watcher;
};
typedef struct skcp_udp_conn_s skcp_udp_conn_t;

struct skcp_tcp_conn_s {
    int fd;
    uint32_t cid;
    struct ev_io* r_watcher;
    struct ev_io* w_watcher;
    void* ctx;
    UT_hash_handle hh;
};
typedef struct skcp_tcp_conn_s skcp_tcp_conn_t;

/* typedef enum { SKCP_NET_CMD_KCP = 0, SKCP_NET_CMD_PING, SKCP_NET_CMD_PONG } skcp_net_cmd_t; */

/* typedef enum { SKCP_NET_CHAN_KCP = 1, SKCP_NET_CHAN_TCP, SKCP_NET_CHAN_UDP } skcp_net_channel_t; */

/* struct skcp_net_s {
    skcp_t* skcp;
    struct ev_loop* loop;
    char* rcv_buf;
};
typedef struct skcp_net_s skcp_net_t; */

typedef void (*skcp_rcv_cb_t)(int cid, const char* buf, int len);

int skcp_init_udp(const char* ip, unsigned short port, struct sockaddr_in* sock, int is_bind);
/* int skcp_init_tcp_server(); */
int skcp_tcp_read(int fd, char* buf, int len);
int skcp_tcp_send(int fd, const char* buf, int len);

int skcp_net_set_reuseaddr(int fd);
int skcp_net_set_nonblocking(int fd);

#endif /* SKCP_NET_H */
