#ifndef _SKCP_CLIENT_H
#define _SKCP_CLIENT_H

#include "skcp_net.h"

typedef char* (*skcp_client_auth_info_cb_t)(int* len);

struct skcp_client_s {
    SKCP_NET_BASE_FIELDS;

    uint32_t cid;
    skcp_tcp_conn_t* tcp_conn;

    /* struct ev_io* tcp_r_watcher; */
    struct ev_io* udp_r_watcher;

    skcp_client_auth_info_cb_t auth_info_cb;
};
typedef struct skcp_client_s skcp_client_t;

skcp_client_t* skcp_client_init(struct ev_loop* loop, const char* tcp_ip, uint16_t tcp_port, const char* udp_ip,
                                uint16_t udp_port, skcp_conf_t* skcp_conf);
void skcp_client_free(skcp_client_t* cli);
void skcp_client_close_conn(skcp_client_t* cli, uint32_t cid);
void skcp_client_set_cb(skcp_client_t* cli, skcp_rcv_cb_t rcv_cb, skcp_client_auth_info_cb_t auth_info_cb);

#endif /* _SKCP_CLIENT_H */