#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "skcp.h"

#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)

static struct ev_timer *send_watcher = NULL;
static uint32_t g_cid = 0;
static skcp_t *skcp = NULL;

static void on_recv_cid(skcp_t *skcp, uint32_t cid) {
    _LOG("on_recv cid: %u", cid);
    g_cid = cid;
    return;
}

static void on_recv_data(skcp_t *skcp, uint32_t cid, char *buf, int buf_len) {
    char msg[10000] = {0};
    if (buf_len > 0) {
        memcpy(msg, buf, buf_len);
    }
    _LOG("client on_recv cid: %u len: %d  msg: %s", cid, buf_len, msg);
}
static void on_close(skcp_t *skcp, uint32_t cid) {
    _LOG("server on_close cid: %u", cid);
    // g_conn = NULL;
    g_cid = 0;
}

static void send_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("send_cb got invalid event");
        return;
    }
    int rt;

    skcp_conn_t *conn = skcp_get_conn(skcp, g_cid);

    if (conn && conn->status == SKCP_CONN_ST_ON) {
        // connection alive
        char msg[10000] = {0};
        // int i = 0;
        // for (; i < 1000; i++) {
        //     msg[i] = 'a';
        // }
        // for (; i < 2000; i++) {
        //     msg[i] = 'b';
        // }
        // for (; i < 3000; i++) {
        //     msg[i] = 'd';
        // }
        // for (; i < 4000; i++) {
        //     msg[i] = 'e';
        // }
        // for (; i < 5000; i++) {
        //     msg[i] = 'f';
        // }
        // for (; i < 6000; i++) {
        //     msg[i] = 'g';
        // }

        sprintf(msg, "hello %lu", clock());
        rt = skcp_send(skcp, g_cid, msg, strlen(msg));
        assert(rt >= 0);

        return;
    }

    skcp_t *skcp = (skcp_t *)watcher->data;

    char ticket[] = "12345678901234567890123456789012";
    rt = skcp_req_cid(skcp, ticket, strlen(ticket));
    assert(rt > 0);
    _LOG("send ticket");
}

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

    conf->addr = "127.0.0.1";  //"45.63.84.222";    // argv[1];
    conf->port = 6060;         // atoi(argv[2]);
    memcpy(conf->key, &"12345678123456781234567812345678", SKCP_KEY_LEN);
    // conf->key = "12345678123456781234567812345678";
    conf->kcp_buf_size = 2048;  // 2048;
    conf->timeout_interval = 1;
    conf->max_conn_cnt = 1024;

    conf->on_close = on_close;
    conf->on_recv_cid = on_recv_cid;
    conf->on_recv_data = on_recv_data;

    if (argc == 3) {
        if (argv[1]) {
            conf->addr = (char *)argv[1];
        }
        if (argv[2]) {
            conf->port = atoi(argv[2]);
        }
    }

    skcp = skcp_init(conf, loop, NULL, SKCP_MODE_CLI);
    assert(skcp);

    send_watcher = malloc(sizeof(ev_timer));
    send_watcher->data = skcp;
    ev_init(send_watcher, send_cb);
    ev_timer_set(send_watcher, 1, 2);
    ev_timer_start(skcp->loop, send_watcher);

    ev_run(loop, 0);

    skcp_free(skcp);
    free(conf);

    _LOG("test end...");
    return 0;
}
