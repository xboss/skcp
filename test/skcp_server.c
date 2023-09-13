#include <assert.h>
#include <fcntl.h>
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
struct ev_loop *loop = NULL;
// static uint32_t g_cid = 0;
static char *g_ticket = "xabcdeabcdeabcdeabcdeabcdeabcdey";
static char *g_key = "12345678901234567890123456789012";
skcp_conf_t *conf = NULL;

inline static void char_to_hex(char *src, int len, char *des) {
    char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    while (len--) {
        *(des++) = hex_table[(*src) >> 4];
        *(des++) = hex_table[*(src++) & 0x0f];
    }
}

static void on_accept(skcp_t *skcp, uint32_t cid) {
    _LOG("server accept cid: %u", cid);
    // g_cid = cid;
}
static void on_recv_data(skcp_t *skcp, uint32_t cid, char *buf, int buf_len) {
    assert(buf);
    assert(buf_len > 0);

    char *msg = (char *)calloc(1, buf_len + 1);
    memcpy(msg, buf, buf_len);
    _LOG("server on_recv cid: %u len: %d  msg: %s", cid, buf_len, msg);

    int rt = skcp_send(skcp, cid, msg, buf_len);
    assert(rt >= 0);
    free(msg);
}
static void on_close(skcp_t *skcp, uint32_t cid) {
    _LOG("server on_close cid: %u", cid);
    // if (cid == g_cid) {
    //     g_cid = 0;
    // }
}
static int on_check_ticket(skcp_t *skcp, char *ticket, int len) { return 0; }

#define SKCP_SERV_USAGE \
    fprintf(stderr,     \
            "Usage: skcp_server [-a address] [-p port] [-k password]\n\
    -a<address> listening address\n\
    -p<port> listening port\n\
    -k<password> password agreed with the client\n\
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
                SKCP_SERV_USAGE;
                return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                    main                                    */
/* -------------------------------------------------------------------------- */
int main(int argc, char const *argv[]) {
    // _LOG("test start...");

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

    conf->on_accept = on_accept;
    conf->on_check_ticket = on_check_ticket;
    conf->on_close = on_close;
    conf->on_recv_data = on_recv_data;

    if (parse_args(conf, argc, argv) != 0) {
        return 1;
    }
    // _LOG("server start, listening on %s %u", conf->addr, conf->port);
    fprintf(stderr, "server start, listening on %s %u\n", conf->addr, conf->port);

    skcp = skcp_init(conf, loop, NULL, SKCP_MODE_SERV);
    assert(skcp);

    ev_run(loop, 0);

    skcp_free(skcp);
    free(conf);

    // _LOG("test end...");
    return 0;
}
