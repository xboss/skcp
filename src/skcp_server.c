#include "skcp_server.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_BACKLOG 128

struct skcp_tcp_conn_s {
    int fd;
    uint32_t cid;
    struct ev_io* r_watcher;
    skcp_server_t* serv;
    UT_hash_handle hh;
};

struct skcp_udp_conn_s {
    int fd;
    uint32_t cid;
    int ticket_id;
    struct sockaddr_in target_sockaddr;
    struct ev_timer* update_watcher;
    skcp_server_t* serv;
};
typedef struct skcp_udp_conn_s skcp_udp_conn_t;

struct skcp_ticket_s {
    int ticket_id;
    uint32_t cid;
    UT_hash_handle hh;
};

#define _CHECK_EV                  \
    if (EV_ERROR & revents) {      \
        _LOG("got invalid event"); \
        return;                    \
    }

/* ----------------------------------------- */

static int gen_ticket_id(skcp_server_t* serv) {
    assert(serv);
    int id;
    skcp_ticket_t* ticket = NULL;
    do {
        id = rand() % 100000000;
        HASH_FIND_INT(serv->ticket_tb, &id, ticket);
    } while (ticket);
    return id;
}

static uint32_t gen_cid(skcp_server_t* serv) {
    assert(serv);
    uint32_t cid = 0;
    do {
        cid = (uint32_t)rand() % 900000000 + 100000000;
    } while (skcp_get_conn(serv->skcp, cid));
    return cid;
}

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

static void close_tcp_conn(skcp_tcp_conn_t* c) { /* TODO: */ }

inline static skcp_udp_conn_t* get_udp_conn(skcp_conn_t* skcp_conn) {
    assert(skcp_conn);
    skcp_udp_conn_t* c = (skcp_udp_conn_t*)skcp_conn->ud;
    assert(c);
    return c;
}

static void update_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    _CHECK_EV;
    assert(watcher);
    skcp_conn_t* conn = (skcp_conn_t*)(watcher->data);
    assert(conn);
    assert(conn->id > 0);
    skcp_update(conn->skcp, conn->id);
}

static skcp_conn_t* new_udp_conn(skcp_server_t* serv, uint32_t cid, int ticket_id) {
    skcp_conn_t* skcp_conn = skcp_init_conn(serv->skcp, cid);
    if (!skcp_conn) {
        return NULL;
    }
    skcp_udp_conn_t* _ALLOC(udp_conn, skcp_udp_conn_t*, sizeof(skcp_udp_conn_t));
    udp_conn->cid = skcp_conn->id;
    udp_conn->fd = serv->udp_fd;
    udp_conn->serv = serv;
    udp_conn->ticket_id = ticket_id;
    udp_conn->update_watcher = NULL;
    _ALLOC(udp_conn->update_watcher, struct ev_timer*, sizeof(struct ev_timer));
    double kcp_interval = serv->skcp->conf.kcp_interval / 1000.0;
    udp_conn->update_watcher->data = serv;
    ev_init(udp_conn->update_watcher, update_cb);
    ev_timer_set(udp_conn->update_watcher, 0, kcp_interval);
    ev_timer_start(serv->loop, udp_conn->update_watcher);
    skcp_conn->ud = udp_conn;
    return skcp_conn;
}

/* ----------------------------------------- */

static void on_tcp_rcv(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("got invalid event");
        return;
    }
    skcp_tcp_conn_t* conn = (skcp_tcp_conn_t*)watcher->data;
    assert(conn);
    assert(conn->fd);
    skcp_server_t* serv = conn->serv;
    assert(serv);
    /* once read */
    int ret = skcp_tcp_read(conn->fd, serv->rcv_buf, serv->rw_buf_size);
    if (ret <= 0) {
        close_tcp_conn(conn);
        return;
    }
    int auth_ret = 1;
    if (serv->auth_cb) {
        auth_ret = serv->auth_cb(serv->rcv_buf, ret);
    }
    if (!auth_ret) {
        _LOG("tcp auth error, close fd:%d", conn->fd);
        close_tcp_conn(conn);
        return;
    }
    /* new skcp conn */
    assert(serv->skcp);
    conn->cid = gen_cid(serv);
    int ticket_id = gen_ticket_id(serv);
    skcp_conn_t* skcp_conn = new_udp_conn(serv, conn->cid, ticket_id);
    if (!skcp_conn) {
        _LOG("init skcp conn error, close fd:%d", conn->fd);
        close_tcp_conn(conn);
        return;
    }
    skcp_ticket_t* _ALLOC(ticket, skcp_ticket_t*, sizeof(skcp_ticket_t));
    HASH_ADD_INT(serv->ticket_tb, ticket_id, ticket);
    /* pack */
    char ack[sizeof(conn->cid) + sizeof(ticket_id)];
    int ncid = htonl(conn->cid);
    int nticket_id = htonl(ticket_id);
    memcpy(ack, &ncid, sizeof(ncid));
    memcpy(ack + sizeof(ncid), &nticket_id, sizeof(nticket_id));
    char cipher_buf[sizeof(conn->cid) + sizeof(ticket_id) + 16];
    memset(cipher_buf, 0, sizeof(cipher_buf));
    int cipher_len = 0;
    /* encrypt */
    ret = skcp_encrypt(serv->skcp->conf.key, ack, sizeof(ack), (char**)&cipher_buf, &cipher_len);
    if (ret != _OK) {
        _LOG("tcp ack encrypt error, close fd:%d", conn->fd);
        skcp_close_conn(serv->skcp, conn->cid);
        conn->cid = 0;
        close_tcp_conn(conn);
        return;
    }
    assert(cipher_len <= sizeof(cipher_buf));
    /* send back cid and ticket_id */
    ret = skcp_tcp_send(conn->fd, cipher_buf, cipher_len);
    close_tcp_conn(conn);
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

static void on_rcv_ping(const char* buf, int len) {
    /* TODO: */
}

static void on_udp_rcv(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("got invalid event");
        return;
    }
    skcp_server_t* serv = (skcp_server_t*)watcher->data;
    assert(serv);
    skcp_t* skcp = serv->skcp;
    assert(skcp);

    struct sockaddr_in target_sockaddr;
    socklen_t addr_len = sizeof(target_sockaddr);
    int rlen = 0, r = 0;
    uint32_t cid = 0;
    char* tmp_buf = NULL;
    int tmp_len = 0;
    do {
        rlen = recvfrom(serv->udp_fd, serv->rcv_buf, serv->rw_buf_size, 0, (struct sockaddr*)&target_sockaddr, &addr_len);
        if (rlen <= 0) {
            /* _LOG("udp rcv error %s", strerror(errno)); */
            if ((rlen == -1) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
                /* EAGAIN */
                _LOG("udp read EAGAIN fd:%d errno:%d", serv->udp_fd, errno);
                break;
            }
            /* TODO: error, close? */
            _LOG("udp read error fd:%d errno:%d", serv->udp_fd, errno);
            break;
        }
        assert(rlen <= skcp->conf.kcp_mtu + 16); /* TODO: debug */
        if (rlen > skcp->conf.kcp_mtu + 16) {
            _LOG("udp read length error. fd:%d len:%d", serv->udp_fd, rlen);
            break;
        }
        /* decrypt */
        tmp_buf = (char*)serv->rcv_buf;
        tmp_len = rlen;
        if (skcp->conf.key[0] != '\0') {
            int ret = skcp_decrypt(skcp->conf.key, serv->rcv_buf, rlen, &skcp->cipher_buf, &tmp_len);
            if (ret != _OK) break;
            tmp_buf = skcp->cipher_buf;
            _LOG("decrypt");
        }
        if (tmp_len < SKCP_NET_UDP_HEAD_LEN) {
            _LOG("udp read head length error. fd:%d len:%d", serv->udp_fd, tmp_len);
            break;
        }

        /* upack header */
        char cmd = *tmp_buf;
        int ticket_id = ntohl(*((int*)tmp_buf));
        /* cid = ntohl(*((int*)(tmp_buf + 4))); */
        /* auth */
        skcp_ticket_t* ticket = NULL;
        HASH_FIND_INT(serv->ticket_tb, &ticket_id, ticket);
        if (!ticket) {
            _LOG("udp read ticket_id:%d error. fd:%d", ticket_id, serv->udp_fd);
            break;
        }
        /* dispatch cmd */
        if (cmd == SKCP_NET_CMD_PING) {
            on_rcv_ping(tmp_buf + SKCP_NET_UDP_HEAD_LEN, tmp_len - SKCP_NET_UDP_HEAD_LEN);
            break;
        }
        cid = ticket->cid;
        skcp_conn_t* c = skcp_get_conn(skcp, cid);
        if (!c) {
            _LOG("udp read cid:%u does not exist", cid);
            break;
        }
        if (ticket_id != get_udp_conn(c)->ticket_id) {
            _LOG("udp read ticket_id:%d error. fd:%d cid:%u", ticket_id, serv->udp_fd, cid);
            break;
        }
        if (skcp_get_cid(tmp_buf) != cid) {
            _LOG("udp read cid:%d not match error. fd:%d cid:%u", cid, serv->udp_fd, cid);
            break;
        }
        cid = skcp_input(skcp, tmp_buf, tmp_len);
        if (cid <= 0) {
            _LOG("skcp_input error. fd:%d cid:%d", serv->udp_fd, cid);
            break;
        }
        get_udp_conn(c)->target_sockaddr = target_sockaddr;
        _LOG("udp rcv fd:%d len:%d", serv->udp_fd, tmp_len);
        r = 0;
        do {
            memset(serv->rcv_buf, 0, serv->rw_buf_size);
            r = skcp_rcv(skcp, cid, serv->rcv_buf, serv->rw_buf_size);
            if (r < 0) break;
            if (serv->skcp_rcv_cb) {
                serv->skcp_rcv_cb(cid, serv->rcv_buf, r);
            }
        } while (r > 0);
    } while (rlen > 0);
}

static int skcp_output_cb(skcp_t* skcp, uint32_t cid, const char* buf, int len) {
    skcp_conn_t* conn = skcp_get_conn(skcp, cid);
    assert(conn);
    /* encrypt */
    char* tmp_buf = (char*)buf;
    int tmp_len = len;
    if (conn->skcp->conf.key[0] != '\0') {
        int ret = skcp_encrypt(conn->skcp->conf.key, buf, len, &conn->skcp->cipher_buf, &tmp_len);
        if (ret != _OK) return _ERR;
        assert(tmp_len <= conn->skcp->conf.kcp_mtu + 16);
        tmp_buf = conn->skcp->cipher_buf;
        _LOG("encrypt");
    }
    skcp_server_t* serv = (skcp_server_t*)conn->skcp->user_data;
    assert(serv);
    int ret = sendto(serv->udp_fd, buf, len, 0, (struct sockaddr*)&(get_udp_conn(conn)->target_sockaddr), sizeof(get_udp_conn(conn)->target_sockaddr));
    if (ret <= 0) {
        _LOG("udp send error %s", strerror(errno));
        return _ERR;
    }
    _LOG("udp send ok. rawlen:%d len:%d", len, ret);
    return ret;
}

/* ----------------------------------------- */

skcp_server_t* skcp_server_init(struct ev_loop* loop, const char* tcp_listen_ip, uint16_t tcp_listen_port, const char* udp_listen_ip, uint16_t udp_listen_port, skcp_conf_t* skcp_conf) {
    /* TODO: check param*/

    srand((unsigned)time(NULL));
    skcp_server_t* _ALLOC(serv, skcp_server_t*, sizeof(skcp_server_t));
    memset(serv, 0, sizeof(skcp_server_t));
    serv->loop = loop;
    serv->udp_fd = skcp_init_udp(udp_listen_ip, udp_listen_port, &serv->udp_sockaddr, 1);
    if (serv->udp_fd <= 0) {
        skcp_server_free(serv);
        return NULL;
    }
    skcp_conf->skcp_output_cb = skcp_output_cb;
    /* serv->ticket_id_set = iset_init(0); */
    skcp_t* skcp = skcp_init(skcp_conf, serv);
    if (!skcp) {
        skcp_server_free(serv);
        return NULL;
    }
    serv->rw_buf_size = skcp->conf.kcp_mtu + 16;
    _ALLOC(serv->rcv_buf, char*, serv->rw_buf_size);

    serv->tcp_server_fd = init_tcp_server(tcp_listen_ip, tcp_listen_port);
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

void skcp_server_close_kcp_conn(skcp_server_t* serv, uint32_t cid) {
    if (!serv) return;
    assert(serv->skcp);
    if (serv->ticket_tb) {
        skcp_conn_t* conn = skcp_get_conn(serv->skcp, cid);
        if (conn) {
            skcp_udp_conn_t* udp_conn = (skcp_udp_conn_t*)conn->ud;
            assert(udp_conn);
            skcp_ticket_t* ticket = NULL;
            HASH_FIND_INT(serv->ticket_tb, &udp_conn->ticket_id, ticket);
            if (ticket) {
                assert(ticket->cid == cid);
                HASH_DEL(serv->ticket_tb, ticket);
            }
            ev_timer_stop(serv->loop, udp_conn->update_watcher);
            free(udp_conn->update_watcher);
        }
    }
    skcp_close_conn(serv->skcp, cid);
}

void skcp_server_set_cb(skcp_server_t* serv, skcp_rcv_cb_t rcv_cb, skcp_server_auth_cb_t auth_cb) {
    if (!serv) return;
    serv->skcp_rcv_cb = rcv_cb;
    serv->auth_cb = auth_cb;
}
