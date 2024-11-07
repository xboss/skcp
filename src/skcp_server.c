#include "skcp_server.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LISTEN_BACKLOG 128

struct skcp_tcp_conn_s {
    int fd;
    int cid;
    struct ev_io* r_watcher;
    skcp_server_t* serv;
    UT_hash_handle hh;
};

/* ----------------------------------------- */

static int init_tcp_server(const char* listen_ip, uint16_t listen_port) {
    int listen_fd = -1;
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("init_tcp_server socket error");
        return _ERR;
    }
    int ret = skcp_net_set_nonblocking(listen_fd);
    if (ret != _OK) {
        perror("init_tcp_server set nonblocking error");
        close(listen_fd);
        return _ERR;
    }
    ret = skcp_net_set_reuseaddr(listen_fd);
    if (ret != _OK) {
        perror("init_tcp_server set reuse addr error");
        close(listen_fd);
        return _ERR;
    }
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr(listen_ip);
    sockaddr.sin_port = htons(listen_port);
    ret = bind(listen_fd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr));
    if (ret == -1) {
        close(listen_fd);
        perror("init_tcp_server bind error");
        return _ERR;
    }
    ret = listen(listen_fd, LISTEN_BACKLOG);
    if (ret == -1) {
        close(listen_fd);
        perror("init_tcp_server listen error");
        return _ERR;
    }
    _LOG("init tcp server ok. listen_ip:%s listen_port:%u fd:%d", listen_ip, listen_port, listen_fd);
    return listen_fd;
}

static int gen_ticket_id(skcp_server_t* serv) { return rand() % 100000000; }

static uint32_t gen_cid(skcp_server_t* serv) {
    uint32_t cid = 0;
    do {
        cid = (uint32_t)rand() % 900000000 + 100000000;
    } while (skcp_get_conn(serv->skcp, cid));
    return cid;
}

/* ----------------------------------------- */

static void close_tcp_conn(skcp_tcp_conn_t* c) { /* TODO: */ }

static void on_tcp_rcv(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("got invalid event");
        return;
    }
    skcp_tcp_conn_t* conn = (skcp_tcp_conn_t*)watcher->data;
    assert(conn);
    /* auth */
    /* new skcp conn */
    /* send back cid and tick_id */
    /* conn->cid = gen_cid(serv); */
    /* TODO: */
}

static void on_accept(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("got invalid event");
        return;
    }
    skcp_server_t* serv = (skcp_server_t*)watcher->data;
    assert(serv);

    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int cli_fd = accept(watcher->fd, (struct sockaddr*)&cli_addr, &cli_len);
    if (cli_fd <= 0) {
        return;
    }
    skcp_net_set_nonblocking(cli_fd);
    skcp_net_set_reuseaddr(cli_fd);

    skcp_tcp_conn_t* _ALLOC(conn, skcp_tcp_conn_t*, sizeof(skcp_tcp_conn_t));
    memset(conn, 0, sizeof(skcp_tcp_conn_t));
    conn->fd = cli_fd;
    conn->serv = serv;

    _ALLOC(conn->r_watcher, struct ev_io*, sizeof(struct ev_io));
    conn->r_watcher->data = conn;
    ev_io_init(conn->r_watcher, on_tcp_rcv, conn->fd, EV_READ);
    ev_io_start(serv->loop, conn->r_watcher);

    HASH_ADD_INT(serv->tcp_conn_tb, fd, conn);
}

static void on_udp_rcv(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("got invalid event");
        return;
    }

    /* TODO: */
}

/* ----------------------------------------- */

skcp_server_t* skcp_server_init(struct ev_loop* loop, const char* listen_ip, uint16_t listen_port,
                                skcp_conf_t* skcp_conf) {
    /* TODO: check param*/

    srand((unsigned)time(NULL));
    skcp_server_t* _ALLOC(serv, skcp_server_t*, sizeof(skcp_server_t));
    memset(serv, 0, sizeof(skcp_server_t));

    serv->udp_fd = skcp_init_udp(1);
    if (serv->udp_fd <= 0) {
        skcp_server_free(serv);
        return NULL;
    }
    skcp_t* skcp = skcp_init(skcp_conf, NULL);
    if (!skcp) {
        skcp_server_free(serv);
        return NULL;
    }
    serv->rw_buf_size = skcp->conf.mtu + 16;
    _ALLOC(serv->rcv_buf, char*, serv->rw_buf_size);

    serv->tcp_server_fd = init_tcp_server(listen_ip, listen_port);
    if (serv->tcp_server_fd <= 0) {
        skcp_server_free(serv);
        return NULL;
    }

    _ALLOC(serv->serv_r_watcher, struct ev_io*, sizeof(struct ev_io));
    serv->serv_r_watcher->data = serv;
    ev_io_init(serv->serv_r_watcher, on_accept, serv->tcp_server_fd, EV_READ);
    ev_io_start(serv->loop, serv->serv_r_watcher);

    _ALLOC(serv->udp_r_watcher, struct ev_io*, sizeof(struct ev_io));
    serv->udp_r_watcher->data = serv;
    ev_io_init(serv->udp_r_watcher, on_udp_rcv, serv->udp_fd, EV_READ);
    ev_io_start(serv->loop, serv->udp_r_watcher);

    return serv;
}

void skcp_server_free(skcp_server_t* serv) { /* TODO: */ }
