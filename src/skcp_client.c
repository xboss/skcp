#include "skcp_client.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _CHECK_EV                  \
    if (EV_ERROR & revents) {      \
        _LOG("got invalid event"); \
        return;                    \
    }

/* ----------------------------------------- */

static void close_tcp_conn(skcp_tcp_conn_t* c) { /* TODO: */ }

/* ----------------------------------------- */

static void update_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    _CHECK_EV;
    assert(watcher);
    skcp_conn_t* conn = (skcp_conn_t*)(watcher->data);
    assert(conn);
    assert(conn->id > 0);
    skcp_update(conn->skcp, conn->id);
}

static skcp_conn_t* new_udp_conn(skcp_client_t* cli, uint32_t cid, int ticket_id) {
    skcp_conn_t* skcp_conn = skcp_init_conn(cli->skcp, cid);
    if (!skcp_conn) {
        return NULL;
    }
    skcp_udp_conn_t* _ALLOC(udp_conn, skcp_udp_conn_t*, sizeof(skcp_udp_conn_t));
    memset(udp_conn, 0, sizeof(skcp_udp_conn_t));
    udp_conn->cid = skcp_conn->id;
    udp_conn->fd = cli->udp_fd;
    udp_conn->update_watcher = NULL;
    _ALLOC(udp_conn->update_watcher, struct ev_timer*, sizeof(struct ev_timer));
    double kcp_interval = cli->skcp->conf.kcp_interval / 1000.0;
    udp_conn->update_watcher->data = cli;
    ev_init(udp_conn->update_watcher, update_cb);
    ev_timer_set(udp_conn->update_watcher, 0, kcp_interval);
    ev_timer_start(cli->loop, udp_conn->update_watcher);
    skcp_conn->ud = udp_conn;
    return skcp_conn;
}

static int skcp_output_cb(skcp_t* skcp, uint32_t cid, const char* buf, int len) {
    skcp_conn_t* conn = skcp_get_conn(skcp, cid);
    assert(conn);
    /* encrypt */
    char* tmp_buf = (char*)buf;
    int tmp_len = len, ret = 0;
    if (conn->skcp->conf.key[0] != '\0') {
        int ret = skcp_encrypt(conn->skcp->conf.key, buf, len, &conn->skcp->cipher_buf, &tmp_len);
        if (ret != _OK) return _ERR;
        assert(tmp_len <= conn->skcp->conf.kcp_mtu + 16);
        tmp_buf = conn->skcp->cipher_buf;
        _LOG("encrypt");
    }
    /* TODO: */
    _LOG("udp send ok. rawlen:%d len:%d", len, ret);
    return ret;
}

static void on_tcp_rcv(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    _CHECK_EV;
    skcp_tcp_conn_t* conn = (skcp_tcp_conn_t*)watcher->data;
    assert(conn);
    skcp_client_t* cli = (skcp_client_t*)conn->ctx;
    assert(cli);

    int ret = skcp_tcp_read(conn->fd, cli->rcv_buf, cli->rw_buf_size);
    if (ret <= 0 || ret < 8) {
        close_tcp_conn(conn);
        return;
    }
    /* unpack: cid(4B)|ticket_id(4B) */
    uint32_t cid = (uint32_t)ntohl(*(uint32_t*)(cli->rcv_buf));
    int ticket_id = ntohl(*(int*)(cli->rcv_buf + 4));

    skcp_conn_t* skcp_conn = new_udp_conn(cli, conn->cid, ticket_id);
    if (!skcp_conn) {
        _LOG("init skcp conn error, close fd:%d", conn->fd);
        close_tcp_conn(conn);
        return;
    }
    /* TODO: */
}

static void on_tcp_write(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    _CHECK_EV;
    skcp_tcp_conn_t* conn = (skcp_tcp_conn_t*)watcher->data;
    assert(conn);
    skcp_client_t* cli = (skcp_client_t*)conn->ctx;
    assert(cli);
    _ALLOC(conn->r_watcher, struct ev_io*, sizeof(struct ev_io));
    conn->r_watcher->data = conn;
    ev_io_init(conn->r_watcher, on_tcp_rcv, conn->fd, EV_READ);
    ev_io_start(cli->loop, conn->r_watcher);

    ev_io_stop(cli->loop, conn->w_watcher);
    free(conn->w_watcher);
    conn->w_watcher = NULL;
    /* send auth info */
    if (!cli->auth_info_cb) {
        return;
    }
    int auth_len = 0;
    char* auth_info = cli->auth_info_cb(&auth_len);
    if (!auth_info) {
        return;
    }
    if (auth_len <= 0) {
        free(auth_info);
        return;
    }
    int ret, cipher_len = auth_len;
    char* cipher_buf = auth_info;
    if (cli->skcp->conf.key[0] != '\0') {
        cipher_len += 16;
        _ALLOC(cipher_buf, char*, cipher_len)
        /* encrypt */
        ret = skcp_encrypt(cli->skcp->conf.key, auth_info, auth_len, (char**)&cipher_buf, &cipher_len);
        if (ret != _OK) {
            _LOG("tcp send auth info encrypt error, close fd:%d", conn->fd);
            free(cipher_buf);
            close_tcp_conn(conn);
            return;
        }
        assert(cipher_len <= sizeof(cipher_buf));
    }

    ret = -1;
    while (ret == -1) {
        /* EAGAIN */
        ret = skcp_tcp_send(conn->fd, cipher_buf, auth_len);
        _LOG("tcp send auth info fd:%d ret:%d", conn->fd, ret);
        sleep(1);
    }
    if (ret <= 0) {
        close_tcp_conn(conn);
    }
    if (cipher_buf != auth_info) free(cipher_buf);
    free(auth_info);
}

static void on_udp_rcv(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    _CHECK_EV;
    /* TODO: */
}

/* return: >0:success fd */
static skcp_tcp_conn_t* tcp_connect(skcp_client_t* cli, const char* ip, unsigned short port) {
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == fd) {
        perror("socket error");
        return NULL;
    }
    skcp_net_set_nonblocking(fd);
    /* skcp_net_set_reuseaddr(fd); */
    int is_pending = 0;
    int rt = connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    if (0 != rt) {
        if (errno != EINPROGRESS) {
            /* error */
            perror("tcp connect error");
            close(fd);
            return NULL;
        } else {
            /* pending */
            _LOG("tcp connect pending...... fd:%d", fd);
            is_pending = 1;
        }
    } else {
        /* connect ok */
        _LOG("tcp connect ok. fd: %d", fd);
    }
    skcp_tcp_conn_t* _ALLOC(conn, skcp_tcp_conn_t*, sizeof(skcp_tcp_conn_t));
    memset(conn, 0, sizeof(skcp_tcp_conn_t));
    conn->fd = fd;
    conn->ctx = cli;
    if (is_pending) {
        _ALLOC(conn->w_watcher, struct ev_io*, sizeof(struct ev_io));
        conn->w_watcher->data = conn;
        ev_io_init(conn->w_watcher, on_tcp_write, conn->fd, EV_WRITE);
        ev_io_start(cli->loop, conn->w_watcher);
    }
    return conn;
}

/* ----------------------------------------- */

skcp_client_t* skcp_client_init(struct ev_loop* loop, const char* tcp_ip, uint16_t tcp_port, const char* udp_ip,
                                uint16_t udp_port, skcp_conf_t* skcp_conf) {
    /* TODO: check param*/

    skcp_client_t* _ALLOC(cli, skcp_client_t*, sizeof(skcp_client_t));
    memset(cli, 0, sizeof(skcp_client_t));
    cli->loop = loop;
    cli->udp_fd = skcp_init_udp(udp_ip, udp_port, &cli->udp_sockaddr, 0);
    if (cli->udp_fd <= 0) {
        skcp_client_free(cli);
        return NULL;
    }
    skcp_conf->skcp_output_cb = skcp_output_cb;
    /* cli->ticket_id_set = iset_init(0); */
    skcp_t* skcp = skcp_init(skcp_conf, cli);
    if (!skcp) {
        skcp_client_free(cli);
        return NULL;
    }
    cli->rw_buf_size = skcp->conf.kcp_mtu + 16;
    _ALLOC(cli->rcv_buf, char*, cli->rw_buf_size);

    cli->tcp_conn = tcp_connect(cli, tcp_ip, tcp_port);
    if (!cli->tcp_conn) {
        skcp_client_free(cli);
        return NULL;
    }

    _ALLOC(cli->udp_r_watcher, struct ev_io*, sizeof(struct ev_io));
    cli->udp_r_watcher->data = cli;
    ev_io_init(cli->udp_r_watcher, on_udp_rcv, cli->udp_fd, EV_READ);
    ev_io_start(cli->loop, cli->udp_r_watcher);

    /* TODO: */
    return cli;
}

void skcp_client_free(skcp_client_t* cli) {
    /* TODO: */
    return;
}

void skcp_client_close_conn(skcp_client_t* cli, uint32_t cid) {
    /* TODO: */
    return;
}

void skcp_client_set_cb(skcp_client_t* cli, skcp_rcv_cb_t rcv_cb, skcp_client_auth_info_cb_t auth_info_cb) {
    if (!cli) return;
    cli->skcp_rcv_cb = rcv_cb;
    cli->auth_info_cb = auth_info_cb;
}
