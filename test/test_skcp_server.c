#include <assert.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "skcp_server.h"

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

void skcp_rcv_cb(int cid, const char* buf, int len) {
    /* TODO: */
    return;
}

 int skcp_server_auth_cb(const char* buf, int len) {
    /* TODO: */
    return 1;
}


int main(int argc, char const* argv[]) {
    _LOG("test start...");
    char udp_ip[INET_ADDRSTRLEN + 1];
    uint16_t udp_port = 0u;
    char tcp_ip[INET_ADDRSTRLEN + 1];
    uint16_t tcp_port = 0u;

    skcp_conf_t conf;
    memset(&conf, 0, sizeof(skcp_conf_t));
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <udp ip> <udp prot> <tcp ip> <tcp prot> <password>\n", argv[0]);
        return 1;
    }

    memcpy(udp_ip, argv[1], strnlen(argv[1], INET_ADDRSTRLEN));
    udp_port = atoi(argv[2]);
    if (argv[5] && strnlen(argv[5], SKCP_CIPHER_KEY_LEN) > 0) {
        memcpy(conf.key, argv[5], strnlen(argv[5], SKCP_CIPHER_KEY_LEN));
    }
    if (udp_ip[0] == '\0' || udp_ip[INET_ADDRSTRLEN] != '\0') {
        fprintf(stderr, "'udp ip' error.\n");
        return 1;
    }
    if (udp_port > 65535 || udp_port <= 0) {
        fprintf(stderr, "'udp port' error. %u\n", udp_port);
        return 1;
    }

    memcpy(tcp_ip, argv[1], strnlen(argv[1], INET_ADDRSTRLEN));
    tcp_port = atoi(argv[2]);
    if (argv[5] && strnlen(argv[5], SKCP_CIPHER_KEY_LEN) > 0) {
        memcpy(conf.key, argv[5], strnlen(argv[5], SKCP_CIPHER_KEY_LEN));
    }
    if (tcp_ip[0] == '\0' || tcp_ip[INET_ADDRSTRLEN] != '\0') {
        fprintf(stderr, "'tcp ip' error.\n");
        return 1;
    }
    if (tcp_port > 65535 || tcp_port <= 0) {
        fprintf(stderr, "'tcp port' error. %u\n", tcp_port);
        return 1;
    }

    conf.mode = 1;
    conf.kcp_interval = 10;
    conf.kcp_mtu = 1024;
    conf.kcp_rcvwnd = 128;
    conf.kcp_sndwnd = 128;
    conf.kcp_nodelay = 1;
    conf.kcp_resend = 2;
    conf.kcp_nc = 1;

    struct ev_loop* loop;
#if (defined(__linux__) || defined(__linux))
    loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    loop = ev_default_loop(0);
#endif

    skcp_server_t* serv = skcp_server_init(loop, tcp_ip, tcp_port, udp_ip, udp_port, &conf);
    assert(serv);
    skcp_server_set_cb(serv, skcp_rcv_cb, skcp_server_auth_cb);

    _LOG("server start, udp listening on %s %u, tcp listenging on %s %u\n", udp_ip, udp_port, tcp_ip, tcp_port);

    ev_run(loop, 0);

    skcp_server_free(serv);

    _LOG("test end...");
    return 0;
}
