#ifndef _SKCP_SERVER_H
#define _SKCP_SERVER_H

#include "skcp_net.h"
/* #include "iset.h" */

typedef int (*skcp_server_auth_cb_t)(const char* buf, int len);

typedef struct skcp_ticket_s skcp_ticket_t;

struct skcp_server_s {
    SKCP_NET_BASE_FIELDS;

    /* iset_t *ticket_id_set; */
    skcp_ticket_t* ticket_tb;
    int tcp_server_fd;
    skcp_tcp_conn_t* tcp_conn_tb;
    struct ev_io* serv_r_watcher;
    struct ev_io* udp_r_watcher;

    skcp_server_auth_cb_t auth_cb;
};
typedef struct skcp_server_s skcp_server_t;

skcp_server_t* skcp_server_init(struct ev_loop* loop, const char* tcp_listen_ip, uint16_t tcp_listen_port,
                                const char* udp_listen_ip, uint16_t udp_listen_port, skcp_conf_t* skcp_conf);
void skcp_server_free(skcp_server_t* serv);
void skcp_server_close_kcp_conn(skcp_server_t* serv, uint32_t cid);
void skcp_server_set_cb(skcp_server_t* serv, skcp_rcv_cb_t rcv_cb, skcp_server_auth_cb_t auth_cb);

#endif /* SKCP_SERVER_H */