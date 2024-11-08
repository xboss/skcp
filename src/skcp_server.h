#ifndef _SKCP_SERVER_H
#define _SKCP_SERVER_H

#include "skcp_net.h"

typedef void (*skcp_rcv_cb_t)(int cid, const char* buf, int len);
typedef int (*skcp_server_auth_cb_t)(const char* buf, int len);

typedef struct skcp_tcp_conn_s skcp_tcp_conn_t;

struct skcp_server_s {
    skcp_t* skcp;
    struct ev_loop* loop;
    char* rcv_buf;
    int udp_fd;
    int rw_buf_size;
    struct sockaddr_in udp_sockaddr;

    int tcp_server_fd;
    skcp_tcp_conn_t* tcp_conn_tb;
    struct ev_io* serv_r_watcher;
    struct ev_io* udp_r_watcher;

    skcp_rcv_cb_t skcp_rcv_cb;
    skcp_server_auth_cb_t auth_cb;
};
typedef struct skcp_server_s skcp_server_t;

skcp_server_t* skcp_server_init(struct ev_loop* loop, const char* tcp_listen_ip, uint16_t tcp_listen_port,
                                const char* udp_listen_ip, uint16_t udp_listen_port, skcp_conf_t* skcp_conf);
void skcp_server_free(skcp_server_t* serv);

#endif /* SKCP_SERVER_H */