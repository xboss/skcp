#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
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

static struct ev_timer *beat_watcher = NULL;
static uint32_t g_cid = 0;
static char *g_ticket = "12345678901234567890123456789012";
static char *g_key = "12345678123456781234567812345678";
skcp_conf_t *conf = NULL;
static skcp_t *skcp = NULL;
struct ev_loop *loop = NULL;
uint64_t msg_id = 0;

inline static void char_to_hex(char *src, int len, char *des) {
    char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    while (len--) {
        *(des++) = hex_table[(*src) >> 4];
        *(des++) = hex_table[*(src++) & 0x0f];
    }
}

static int on_check_ticket(skcp_t *skcp, char *ticket, int len) { return 0; }

static void on_recv_data(skcp_t *skcp, uint32_t cid, char *buf, int buf_len) {
    assert(buf);
    assert(buf_len > 0);

    // char msg[SKCP_MAX_RW_BUF_LEN] = {0};
    char *msg = (char *)calloc(1, buf_len + 1);
    memcpy(msg, buf, buf_len);
    _LOG("client on_recv cid: %u len: %d  msg: %s", cid, buf_len, msg);
    free(msg);
}
static void on_close(skcp_t *skcp, uint32_t cid) {
    _LOG("server on_close cid: %u", cid);
    g_cid = 0;
}

static void on_recv_cid(skcp_t *skcp, uint32_t cid) {
    _LOG("on_recv cid: %u", cid);
    g_cid = cid;
    return;
}

static void beat_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (g_cid <= 0) {
        int rt = skcp_req_cid(skcp, g_ticket, strlen(g_ticket));
        assert(rt > 0);
        _LOG("send cid request");
    } else {
        // send msg
        // char msg[SKCP_MAX_RW_BUF_LEN] = "hello from client";
        // sprintf(msg, "%llu hello from client", msg_id++);

#define TEST_MSG_LEN 1501
        char msg[TEST_MSG_LEN] = {0};
        for (size_t i = 0; i < TEST_MSG_LEN; i++) {
            msg[i] = 'X';
        }
        msg[TEST_MSG_LEN - 1] = 'M';

        int rt = skcp_send(skcp, g_cid, msg, sizeof(msg));
        assert(rt >= 0);
    }
}

#define SKCP_CLI_USAGE \
    fprintf(stderr,    \
            "Usage: skcp_client [-a address] [-p port] [-k password]\n\
    -a<address> connection address\n\
    -p<port> connection port\n\
    -k<password> password agreed with the server\n\
    -h help info\n")

inline static void parse_pwd(skcp_conf_t *conf) {
    char padding[16] = {0};
    int len = strlen(optarg);
    len = len > 16 ? 16 : len;
    memcpy(padding, optarg, len);
    char_to_hex(padding, len, conf->key);
}

inline static int parse_args(skcp_conf_t *conf, int argc, char const *argv[]) {
    char opt;
    while ((opt = getopt(argc, (char *const *)argv, "ha:p:k:")) != -1) {
        switch (opt) {
            case 'a':
                conf->addr = optarg;
                break;
            case 'p':
                conf->port = atoi(optarg);
                if (conf->port <= 0) {
                    fprintf(stderr, "invalid port %s\n", optarg);
                    return 1;
                }
                break;
            case 'k':
                parse_pwd(conf);
                break;
            case 'h':
            default:
                SKCP_CLI_USAGE;
                return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                    main                                    */
/* -------------------------------------------------------------------------- */
int main(int argc, char const *argv[]) {
    _LOG("test start...");

#if (defined(__linux__) || defined(__linux))
    loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    loop = ev_default_loop(0);
#endif

    conf = malloc(sizeof(skcp_conf_t));
    memset(conf, 0, sizeof(skcp_conf_t));
    conf->interval = 10;
    // conf->mtu = 1024;
    conf->rcvwnd = 128;
    conf->sndwnd = 128;
    conf->nodelay = 1;
    conf->resend = 2;
    conf->nc = 1;
    conf->r_keepalive = 15;
    conf->w_keepalive = 15;

    conf->addr = "127.0.0.1";
    conf->port = 6060;
    memcpy(conf->key, g_key, SKCP_KEY_LEN);
    memcpy(conf->ticket, g_ticket, SKCP_TICKET_LEN);
    conf->max_conn_cnt = 1024;

    conf->on_check_ticket = on_check_ticket;
    conf->on_close = on_close;
    conf->on_recv_cid = on_recv_cid;
    conf->on_recv_data = on_recv_data;

    if (parse_args(conf, argc, argv) != 0) {
        return 1;
    }

    fprintf(stderr, "client connect %s %u\n", conf->addr, conf->port);

    skcp = skcp_init(conf, loop, NULL, SKCP_MODE_CLI);
    assert(skcp);

    beat_watcher = malloc(sizeof(ev_timer));
    ev_init(beat_watcher, beat_cb);
    ev_timer_set(beat_watcher, 0, 1);
    ev_timer_start(loop, beat_watcher);

    ev_run(loop, 0);

    skcp_free(skcp);
    free(conf);

    _LOG("test end...");
    return 0;
}
