#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "skcp.h"

#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)

static skcp_t *skcp = NULL;

static void on_accept(uint32_t cid) { _LOG("server accept cid: %u", cid); }
static void on_recv_data(uint32_t cid, char *buf, int buf_len) {
    char msg[10000] = {0};
    if (buf_len > 0) {
        memcpy(msg, buf, buf_len);
    }
    _LOG("server on_recv cid: %u len: %d  msg: %s", cid, buf_len, msg);
    int rt = skcp_send(skcp, cid, buf, buf_len);
    assert(rt >= 0);
}
static void on_close(uint32_t cid) { _LOG("server on_close cid: %u", cid); }
static int on_check_ticket(char *ticket, int len) { return 0; }

/* -------------------------------------------------------------------------- */
/*                                    main                                    */
/* -------------------------------------------------------------------------- */
int main(int argc, char const *argv[]) {
    _LOG("test start...");

#if (defined(__linux__) || defined(__linux))
    struct ev_loop *loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    struct ev_loop *loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    struct ev_loop *loop = ev_default_loop(0);
#endif

    skcp_conf_t *conf = malloc(sizeof(skcp_conf_t));
    memset(conf, 0, sizeof(skcp_conf_t));
    conf->interval = 10;
    conf->r_buf_size = conf->mtu = 1024;
    conf->rcvwnd = 128;
    conf->sndwnd = 128;
    conf->nodelay = 1;
    conf->resend = 2;
    conf->nc = 1;
    conf->r_keepalive = 15;  // 600;
    conf->w_keepalive = 15;  // 600;
    conf->estab_timeout = 100;

    conf->addr = "127.0.0.1";  // argv[1];
    conf->port = 6060;         // atoi(argv[2]);
    memcpy(conf->key, &"12345678123456781234567812345678", SKCP_KEY_LEN);
    // conf->key = ;
    conf->kcp_buf_size = 2048;  // 2048;
    conf->timeout_interval = 1;
    conf->max_conn_cnt = 1024;

    conf->on_accept = on_accept;
    conf->on_check_ticket = on_check_ticket;
    conf->on_close = on_close;
    conf->on_recv_data = on_recv_data;

    if (argc == 3) {
        if (argv[1]) {
            conf->addr = (char *)argv[1];
        }
        if (argv[2]) {
            conf->port = atoi(argv[2]);
        }
    }

    skcp = skcp_init(conf, loop, NULL, SKCP_MODE_SERV);
    assert(skcp);

    ev_run(loop, 0);

    skcp_free(skcp);
    free(conf);

    _LOG("test end...");
    return 0;
}
