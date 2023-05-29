#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "skcp.h"

#define SKCP_LOG(fmt, args...) \
    do {                       \
        printf(fmt, ##args);   \
        printf("\n");          \
    } while (0)

static skcp_t *skcp = NULL;
struct ev_loop *loop = NULL;
static uint32_t g_cid = 0;
static struct ev_io *stdin_watcher = NULL;
ev_idle idle;

inline static void char_to_hex(char *src, int len, char *des) {
    char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    while (len--) {
        *(des++) = hex_table[(*src) >> 4];
        *(des++) = hex_table[*(src++) & 0x0f];
    }
}

static void on_created_conn(skcp_t *skcp, uint32_t cid) {
    SKCP_LOG("server accept cid: %u", cid);
    g_cid = cid;
}
static void on_recv(skcp_t *skcp, uint32_t cid, char *buf, int buf_len) {
    SKCP_LOG("server on_recv cid: %u len: %d", cid, buf_len);
    if (!buf || buf_len < 1) {
        fprintf(stderr, "on_recv_data buf error\n");
        return;
    }
    if (buf[0] != 'D' && buf[0] != 'O' && buf[0] != 'I') {
        fprintf(stderr, "on_recv_data cmd error\n");
        return;
    }

    if (buf[0] == 'D') {
        // cmd data
        char *pb = buf + 1;
        fprintf(stdout, ">>>>>>>>>%s", pb);
        fflush(stdout);
        return;
    }

    if (buf[0] == 'I') {
        // cmd ping
        // send pong
        char msg[] = "O";
        int rt = skcp_send(skcp, cid, msg, strlen(msg));
        assert(rt >= 0);
        return;
    }
}
static void on_close(skcp_t *skcp, uint32_t cid, u_char type) {
    SKCP_LOG("server on_close cid: %u", cid);
    if (cid == g_cid) {
        g_cid = 0;
    }
}
static int on_auth(skcp_t *skcp, char *ticket, int len) {
    SKCP_LOG("server on_auth");
    return 0;
}

static void stdin_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    ev_io_stop(loop, watcher);
    ev_idle_start(loop, &idle);
}

static void idle_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents) {
    skcp_conn_t *conn = skcp_get_conn(skcp->conn_slots, g_cid);
    if (conn && conn->status == SKCP_CONN_ST_ON) {
        // connection alive
        char inbuf[1600] = {0};
        inbuf[0] = 'D';
        char *pb = inbuf + 1;
        fread(pb, sizeof(inbuf) - 2, 1, stdin);
        size_t inbuf_len = strlen(inbuf);
        if (inbuf_len > 1) {
            // SKCP_LOG("%s len:%lu", inbuf, inbuf_len);
            int rt = skcp_send(skcp, g_cid, inbuf, inbuf_len);
            assert(rt >= 0);
        }
    }
    // else {
    //     fprintf(stderr, "idle_cb skcp cid not ready\n");
    // }
    ev_io_start(loop, stdin_watcher);
}

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
    // SKCP_LOG("test start...");

#if (defined(__linux__) || defined(__linux))
    loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    loop = ev_default_loop(0);
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
    conf->r_keepalive = 15;
    conf->w_keepalive = 15;
    conf->mode = SKCP_IO_MODE_SERVER;

    conf->addr = "127.0.0.1";
    conf->port = 6060;
    conf->key = SKCP_ALLOC(SKCP_KEY_LEN + 1);
    memcpy(conf->key, &"12345678123456781234567812345678", SKCP_KEY_LEN);
    conf->kcp_buf_size = 2048;
    conf->timeout_interval = 1;
    conf->max_conn_cnt = 1024;

    conf->io_cnt = 1;
    conf->engine_cnt = 1;

    if (parse_args(conf, argc, argv) != 0) {
        return 1;
    }
    // SKCP_LOG("server start, listening on %s %u", conf->addr, conf->port);
    fprintf(stderr, "server start, listening on %s %u\n", conf->addr, conf->port);

    skcp = skcp_init(conf, loop, on_created_conn, on_recv, on_close, on_auth, NULL);
    assert(skcp);

    if (-1 == fcntl(STDOUT_FILENO, F_SETFL, fcntl(STDOUT_FILENO, F_GETFL) | O_NONBLOCK)) {
        fprintf(stderr, "error fcntl");
        return 1;
    }

    ev_idle_init(&idle, idle_cb);

    stdin_watcher = malloc(sizeof(struct ev_io));
    ev_io_init(stdin_watcher, stdin_read_cb, STDIN_FILENO, EV_READ);
    ev_io_start(loop, stdin_watcher);

    ev_run(loop, 0);

    skcp_free(skcp);
    free(conf);

    // SKCP_LOG("test end...");
    return 0;
}
