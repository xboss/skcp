#include <assert.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#define _CHECK_EV                  \
    if (EV_ERROR & revents) {      \
        _LOG("got invalid event"); \
        return;                    \
    }

static skcp_t* g_skcp = NULL;
struct ev_loop* g_loop = NULL;
char g_ip[INET_ADDRSTRLEN + 1];
uint16_t g_port = 0u;
char* g_rcv_buf;
static uint32_t g_cid = 1;
/* static char *g_pwd = "password"; */
/* skcp_conf_t *g_conf = NULL; */

static int set_reuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) return _ERR;
    return _OK;
}

static int set_nonblocking(int fd) {
    int flag = fcntl(fd, F_GETFL, 0);
    if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) == -1) return _ERR;
    return _OK;
}

static int init_network(int is_bind, struct sockaddr_in* target_sockaddr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == fd) {
        perror("init_network socket error");
        return _ERR;
    }
    int ret = set_nonblocking(fd);
    if (ret != _OK) {
        perror("init_network set nonblocking error");
        close(fd);
        return _ERR;
    }
    if (is_bind) {
        ret = set_reuseaddr(fd);
        if (ret != _OK) {
            perror("init_network set reuse addr error");
            close(fd);
            return _ERR;
        }
        struct sockaddr_in sockaddr;
        memset(&sockaddr, 0, sizeof(struct sockaddr_in));
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = inet_addr(g_ip);
        sockaddr.sin_port = htons(g_port);
        ret = bind(fd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr));
        if (ret == -1) {
            perror("init_network bind error");
            close(fd);
            return _ERR;
        }
        _LOG("start udp server ok. listen_ip:%s listen_port:%u fd:%d", g_ip, g_port, fd);
    } else {
        target_sockaddr->sin_family = AF_INET;
        target_sockaddr->sin_port = htons(g_port);
        target_sockaddr->sin_addr.s_addr = inet_addr(g_ip);
        _LOG("init udp client ok. target_ip:%s target_port:%u fd:%d", g_ip, g_port, fd);
    }
    return fd;
}

static int skcp_output_cb(skcp_t* skcp, uint32_t cid, const char* buf, int len) {
    skcp_conn_t* c = skcp_get_conn(skcp, cid);
    assert(c);
    int ret = sendto(skcp->fd, buf, len, 0, (struct sockaddr*)&c->target_sockaddr, sizeof(c->target_sockaddr));
    if (ret <= 0) {
        _LOG("udp send error %s", strerror(errno));
        return -1;
    }
    return ret;
}

static void update_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    _CHECK_EV;
    assert(watcher);
    skcp_conn_t* conn = (skcp_conn_t*)(watcher->data);
    assert(conn);
    assert(conn->id > 0);
    skcp_update(g_skcp, conn->id);
}

static int g_tick = 0;
char g_msg[256];
static void beat_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    _CHECK_EV;
    memset(g_msg, 0, sizeof(g_msg));
    sprintf(g_msg, "hello %d", g_tick++ % 99999999);
    int ret = skcp_send(g_skcp, g_cid, g_msg, strlen(g_msg));
    assert(ret == 0);
    _LOG("client send: %s len:%d", g_msg, strlen(g_msg));
}

static void on_server_rcv(int cid, const char* buf, int len) {
    _LOG("server rcv:%s len:%d cid:%d", buf, len, cid);
    memset(g_msg, 0, sizeof(g_msg));
    memcpy(g_msg, buf, len);
    char *ack = " ack...";
    memcpy(g_msg+len, ack, strlen(ack));
    int ret = skcp_send(g_skcp, cid, g_msg, strlen(g_msg));
    assert(ret == 0);
}
static void on_client_rcv(int cid, const char* buf, int len) {
    _LOG("client rcv:%s len:%d cid:%d", buf, len, cid);
}

static void on_udp_rcv(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    _CHECK_EV;
    socklen_t addr_len = sizeof(g_skcp->target_sockaddr);
    int rlen = 0, r = 0;
    uint32_t cid = 0;
    do {
        rlen = recvfrom(g_skcp->fd, g_rcv_buf, g_skcp->conf.mtu, 0, (struct sockaddr*)&g_skcp->target_sockaddr, &addr_len);
        if (rlen <= 0) {
            /* _LOG("udp rcv error %s", strerror(errno)); */
            break;
        }
        assert(rlen <= g_skcp->conf.mtu);
        cid = skcp_input(g_skcp, g_rcv_buf, rlen);
        assert(cid > 0);
        skcp_conn_t* c = skcp_get_conn(g_skcp, cid);
        assert(c);
        c->target_sockaddr = g_skcp->target_sockaddr;
        _LOG("udp rcv len:%d", rlen);
        r = 0;
        do {
            memset(g_rcv_buf, 0, g_skcp->conf.mtu);
            r = skcp_rcv(g_skcp, cid, g_rcv_buf, g_skcp->conf.mtu);
            if (r < 0) break;
            if (g_skcp->conf.mode == SKCP_MODE_SERV)
                on_server_rcv(cid, g_rcv_buf, r);
            else
                on_client_rcv(cid, g_rcv_buf, r);
        } while (r > 0);
    } while (rlen > 0);
}

/* -------------------------------------------------------------------------- */
/*                                    main                                    */
/* -------------------------------------------------------------------------- */
int main(int argc, char const* argv[]) {
    _LOG("test start...");

    skcp_conf_t conf;
    memset(&conf, 0, sizeof(skcp_conf_t));
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <mode> <ip> <prot> <password>\n", argv[0]);
        return 1;
    }
    conf.mode = atoi(argv[1]);
    memcpy(g_ip, argv[2], strnlen(argv[2], INET_ADDRSTRLEN));
    g_port = atoi(argv[3]);
    if (argv[4] && strnlen(argv[4], SKCP_CIPHER_KEY_LEN) > 0) {
        memcpy(conf.key, argv[4], strnlen(argv[4], SKCP_CIPHER_KEY_LEN));
    }
    if (g_ip[0] == '\0' || g_ip[INET_ADDRSTRLEN] != '\0') {
        fprintf(stderr, "'ip' error.\n");
        return 1;
    }
    if (g_port > 65535 || g_port <= 0) {
        fprintf(stderr, "'port' error. %u\n", g_port);
        return 1;
    }

    conf.interval = 10;
    conf.mtu = 1024;
    conf.rcvwnd = 128;
    conf.sndwnd = 128;
    conf.nodelay = 1;
    conf.resend = 2;
    conf.nc = 1;
    conf.skcp_output_cb = skcp_output_cb;

    int is_bind = 0;
    if (conf.mode == SKCP_MODE_SERV) {
        is_bind = 1;
    }

    struct sockaddr_in target_sockaddr;
    int fd = init_network(is_bind, &target_sockaddr);
    assert(fd > 0);

    g_skcp = skcp_init(fd, &conf, NULL);
    assert(g_skcp);

    _ALLOC(g_rcv_buf, char*, g_skcp->conf.mtu);

#if (defined(__linux__) || defined(__linux))
    g_loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    g_loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    g_loop = ev_default_loop(0);
#endif

    struct ev_io* _ALLOC(r_watcher, struct ev_io*, sizeof(struct ev_io));
    ev_io_init(r_watcher, on_udp_rcv, fd, EV_READ);
    ev_io_start(g_loop, r_watcher);

    skcp_conn_t* newconn = skcp_init_conn(g_skcp, g_cid, target_sockaddr); /* TODO: dynamically init conn*/
    assert(newconn);

    struct ev_timer* update_watcher = NULL;
    struct ev_timer* beat_watcher = NULL;
    if (g_skcp->conf.mode == SKCP_MODE_SERV) {
        /* struct ev_timer *update_watcher; */
        _ALLOC(update_watcher, struct ev_timer*, sizeof(struct ev_timer));
        double kcp_interval = g_skcp->conf.interval / 1000.0;
        update_watcher->data = newconn;
        ev_init(update_watcher, update_cb);
        ev_timer_set(update_watcher, 0, kcp_interval);
        ev_timer_start(g_loop, update_watcher);
        _LOG("server start, listening on %s %u\n", g_ip, g_port);
    } else {
        _ALLOC(beat_watcher, struct ev_timer*, sizeof(struct ev_timer));
        ev_init(beat_watcher, beat_cb);
        ev_timer_set(beat_watcher, 0, 1);
        ev_timer_start(g_loop, beat_watcher);
    }

    ev_run(g_loop, 0);

    free(beat_watcher);
    free(update_watcher);
    free(r_watcher);
    skcp_free(g_skcp);

    _LOG("test end...");
    return 0;
}
