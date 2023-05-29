#include "skcp.h"

#include <assert.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <sys/time.h>
// #include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*                                  protocol                                  */
/* -------------------------------------------------------------------------- */

#define SKCP_CMD_REQ_CID 0x01
#define SKCP_CMD_REQ_CID_ACK 0x02
// #define SKCP_CMD_REQ_CID_COMP 0x02
#define SKCP_CMD_DATA 0x03
// #define SKCP_CMD_PING 0x04
// #define SKCP_CMD_PONG 0x05
// #define SKCP_CMD_CLOSE 0x06
// #define SKCP_CMD_CLOSE_ACK 0x07

#define SKCP_CMD_HEADER_LEN 9

typedef struct {
    uint32_t id;
    u_char type;
    uint32_t payload_len;
    char payload[0];
} skcp_cmd_t;

inline static char *encode_cmd(uint32_t id, u_char type, const char *buf, int len, int *out_len) {
    char *raw = (char *)SKCP_ALLOC(SKCP_CMD_HEADER_LEN + len);
    uint32_t nid = htonl(id);
    memcpy(raw, &nid, 4);
    *(raw + 4) = type;
    uint32_t payload_len = htonl(len);
    memcpy(raw + 5, &payload_len, 4);
    if (len > 0) {
        memcpy(raw + SKCP_CMD_HEADER_LEN, buf, len);
    }
    *out_len = len + SKCP_CMD_HEADER_LEN;

    return raw;
}

inline static skcp_cmd_t *decode_cmd(const char *buf, int len) {
    skcp_cmd_t *cmd = (skcp_cmd_t *)SKCP_ALLOC(sizeof(skcp_cmd_t) + (len - SKCP_CMD_HEADER_LEN));
    // SKCP_LOG("decode_cmd len: %d", len);
    cmd->id = ntohl(*(uint32_t *)buf);
    cmd->type = *(buf + 4);
    cmd->payload_len = ntohl(*(uint32_t *)(buf + 5));
    if (len > SKCP_CMD_HEADER_LEN) {
        memcpy(cmd->payload, buf + SKCP_CMD_HEADER_LEN, cmd->payload_len);
    }
    // SKCP_LOG("decode_cmd len: %d %lu", len, sizeof(*cmd));

    return cmd;
}

/* -------------------------------------------------------------------------- */
/*                                    skcp                                    */
/* -------------------------------------------------------------------------- */

/* ------------------------------- private api ------------------------------ */

static void notify_input_cb(struct ev_loop *loop, struct ev_async *watcher, int revents) {
    skcp_t *skcp = (skcp_t *)watcher->data;
    // send
    while (skcp->in_mq->size > 0) {
        skcp_msg_t *msg = (skcp_msg_t *)skcp_pop_queue(skcp->in_mq);
        // if (!msg) {
        //     continue;
        // }
        if (msg->type == SKCP_MSG_TYPE_RECV) {
            skcp->on_recv(skcp, msg->cid, msg->buf, msg->buf_len);
        } else if (msg->type == SKCP_MSG_TYPE_CLOSE_TIMEOUT || msg->type == SKCP_MSG_TYPE_CLOSE_MANUAL) {
            skcp->on_close(skcp, msg->cid, msg->type);
        } else {
            SKCP_LOG("skcp error msg type %x", msg->type);
        }
        SKCP_FREE_MSG(msg);
    }
}

static void on_req_cid_cmd(skcp_t *skcp, skcp_cmd_t *cmd, struct sockaddr_in dst_addr) {
    const uint ack_len = 1 + 1 + SKCP_TICKET_LEN + 1 + SKCP_IV_LEN + 1;
    // char ack[ack_len] = {0};
    char *ack = (char *)SKCP_ALLOC(ack_len);  // split by "\n", format:"code\ncid\niv"
    int out_len = 0;
    char *buf = NULL;
    uint32_t cid = 0;
    if (cmd->payload_len != SKCP_TICKET_LEN) {
        snprintf(ack, ack_len, "%d", 1);
        goto send_req_cid_ack;
    }

    int rt = skcp->on_auth(skcp, cmd->payload, cmd->payload_len);
    if (rt != 0) {
        // fail
        snprintf(ack, ack_len, "%d", 1);
        goto send_req_cid_ack;
    }

    // skcp_io_t *io = route_to_io(skcp, cid);
    // create connection
    skcp_conn_t *conn = skcp_init_conn(skcp->conn_slots, skcp->conf, 0, skcp->io_list, skcp->conf->io_cnt);
    if (!conn) {
        // fail
        snprintf(ack, ack_len, "%d", 1);
        goto send_req_cid_ack;
    }
    conn->skcp = skcp;
    conn->dst_addr = dst_addr;
    uint idx = skcp_route_engine(conn->id, skcp->conf->engine_cnt);
    skcp_engine_reg_conn(skcp->engine_list[idx], conn);

    // send result ok
    snprintf(ack, ack_len, "%d\n%u", 0, conn->id);
    // snprintf(ack, ack_len, "%d\n%u\n%s", 0, conn->id, conn->iv);
    // _LOG("on_req_cid_cmd ack: %s", ack);
    cid = conn->id;

send_req_cid_ack:
    buf = encode_cmd(0, SKCP_CMD_REQ_CID_ACK, ack, strlen(ack), &out_len);
    SKCP_FREEIF(ack);
    idx = skcp_route_io(cid, skcp->conf->io_cnt);
    rt = skcp_io_send(skcp->io_list[idx], buf, out_len, dst_addr);
    SKCP_FREEIF(buf);
    if (cid > 0) {
        if (rt < 0) {
            skcp_close_conn(skcp, cid);
            return;
        }
        skcp->on_created_conn(skcp, cid);
    }
}

static void on_req_cid_ack_cmd(skcp_t *skcp, skcp_cmd_t *cmd) {
    if (cmd->payload_len <= 0 || cmd->payload[1] != '\n' || cmd->payload[0] != '0' || cmd->payload_len < 3) {
        // error
        SKCP_LOG("on_req_cid_ack_cmd cmd error");
        return;
    }

    // success
    char *p = cmd->payload + 2;
    int i = 0;
    for (; i < cmd->payload_len - 2; i++) {
        if (*p == '\n') {
            break;
        }
        p++;
    }
    int scid_len = p - (cmd->payload + 2);
    char *scid = (char *)SKCP_ALLOC(scid_len + 1);
    memcpy(scid, cmd->payload + 2, scid_len);

    uint32_t cid = atoi(scid);
    SKCP_FREEIF(scid);
    if (cid <= 0) {
        // error
        SKCP_LOG("on_req_cid_ack_cmd cid error");
        return;
    }

    // create connection
    skcp_conn_t *conn = skcp_init_conn(skcp->conn_slots, skcp->conf, cid, skcp->io_list, skcp->conf->io_cnt);
    if (!conn) {
        // error
        SKCP_LOG("on_req_cid_ack_cmd skcp_init_conn error");
        return;
    }
    conn->skcp = skcp;
    uint idx = skcp_route_engine(conn->id, skcp->conf->engine_cnt);
    skcp_engine_reg_conn(skcp->engine_list[idx], conn);

    // memcpy(conn->iv, p + 1, cmd->payload_len - i - 2);
    // conn->status = SKCP_CONN_ST_ON;
    // TODO: set ticket, to the user to resolve

    // _LOG("on_req_cid_ack_cmd cid: %d iv: %s", conn->id, conn->iv);

    skcp->on_created_conn(skcp, conn->id);
}

static void engine_msg_handler(skcp_msg_t *eg_msg) {
    skcp_t *skcp = (skcp_t *)eg_msg->user_data;
    skcp_msg_t *msg = NULL;
    if (eg_msg->type == SKCP_MSG_TYPE_RECV) {
        SKCP_INIT_MSG(msg, SKCP_MSG_TYPE_RECV, eg_msg->cid, eg_msg->buf, eg_msg->buf_len, skcp);
    } else if (SKCP_MSG_TYPE_CLOSE_TIMEOUT == eg_msg->type || SKCP_MSG_TYPE_CLOSE_MANUAL == eg_msg->type) {
        SKCP_INIT_MSG(msg, eg_msg->type, eg_msg->cid, eg_msg->buf, eg_msg->buf_len, skcp);
    } else {
        SKCP_LOG("engine_msg_handler error msg type %x", eg_msg->type);
    }
    if (skcp_push_queue(skcp->in_mq, msg) != 0) {
        SKCP_LOG("recv_msg_handler push in_mq error");
    }
    ev_async_send(skcp->loop, skcp->notify_input_watcher);
}

static void io_msg_handler(skcp_msg_t *io_msg) {
    skcp_t *skcp = (skcp_t *)io_msg->user_data;

    if (io_msg->type == SKCP_MSG_TYPE_DATA) {
        uint32_t cid = 0;
        skcp_decode32u(io_msg->buf, &cid);
        // kcp msg
        skcp_msg_t *eg_msg = NULL;
        SKCP_INIT_ENGINE_MSG(eg_msg, SKCP_MSG_TYPE_INPUT, cid, io_msg->buf, io_msg->buf_len, skcp);
        // SKCP_FREE_MSG(io_msg);
        uint idx = skcp_route_engine(eg_msg->cid, skcp->conf->engine_cnt);
        // skcp_engine_t *engine = route_to_engine(skcp, eg_msg->cid);
        if (skcp_engine_feed(skcp->engine_list[idx], eg_msg) != SKCP_OK) {
            SKCP_LOG("recv_raw_handler skcp_engine_feed error");
        }
    } else if (io_msg->type == SKCP_MSG_TYPE_UDP) {
        // udp msg
        if (io_msg->buf_len < SKCP_CMD_HEADER_LEN) {
            // SKCP_FREE_MSG(io_msg);
            return;
        }
        skcp_cmd_t *cmd = decode_cmd(io_msg->buf, io_msg->buf_len);

        if (!cmd) {
            // _LOG("decode_cmd error");
            // SKCP_FREE_MSG(io_msg);
            return;
        }
        if (cmd->type == SKCP_CMD_REQ_CID) {
            on_req_cid_cmd(skcp, cmd, io_msg->dst_addr);
        } else if (cmd->type == SKCP_CMD_REQ_CID_ACK) {
            on_req_cid_ack_cmd(skcp, cmd);
        } else {
            SKCP_LOG("skcp error io cmd type %x", cmd->type);
        }
        // SKCP_FREE_MSG(io_msg);
        SKCP_FREEIF(cmd);
    } else {
        SKCP_LOG("skcp error io msg type %x", io_msg->type);
    }
}

/* ------------------------------- public api ------------------------------- */

skcp_t *skcp_init(skcp_conf_t *conf, struct ev_loop *loop, on_created_conn_t on_created_conn, on_recv_t on_recv,
                  on_close_t on_close, on_auth_t on_auth, void *user_data) {
    if (!conf || !on_created_conn || !on_recv || !on_close) {
        return NULL;
    }

    skcp_t *skcp = (skcp_t *)SKCP_ALLOC(sizeof(skcp_t));
    skcp->conf = conf;
    skcp->on_auth = on_auth;
    skcp->on_close = on_close;
    skcp->on_created_conn = on_created_conn;
    skcp->on_recv = on_recv;
    skcp->user_data = user_data;
    skcp->loop = loop;

    skcp->conn_slots = skcp_init_conn_slots(conf->max_conn_cnt);
    if (!skcp->conn_slots) {
        skcp_free(skcp);
        return NULL;
    }

    skcp->in_mq = skcp_init_queue(-1);
    if (!skcp->in_mq) {
        skcp_free(skcp);
        return NULL;
    }

    // init engines
    skcp->engine_list = (skcp_engine_t **)SKCP_ALLOC(conf->engine_cnt * sizeof(skcp_engine_t *));
    for (uint i = 0; i < conf->engine_cnt; i++) {
        // struct ev_timer *tick_watcher = (struct ev_timer *)SKCP_ALLOC(sizeof(ev_timer));
        skcp->engine_list[i] = skcp_engine_init(i, skcp->conn_slots, skcp->conf, engine_msg_handler, skcp);
        if (!skcp->engine_list[i]) {
            SKCP_LOG("init engine error %u", i);
            skcp_free(skcp);
            return NULL;
        }
    }

    // init io
    skcp->io_list = (skcp_io_t **)SKCP_ALLOC(conf->io_cnt * sizeof(skcp_io_t *));
    for (uint i = 0; i < conf->io_cnt; i++) {
        // struct ev_timer *tick_watcher = (struct ev_timer *)SKCP_ALLOC(sizeof(ev_timer));
        skcp->io_list[i] = skcp_io_init(conf, io_msg_handler, skcp);
        if (!skcp->io_list[i]) {
            SKCP_LOG("init io error %u", i);
            skcp_free(skcp);
            return NULL;
        }
    }

    // #if (defined(__linux__) || defined(__linux))
    //     skcp->loop = ev_loop_new(EVBACKEND_EPOLL);
    // #elif defined(__APPLE__)
    //     skcp->loop = ev_loop_new(EVBACKEND_KQUEUE);
    // #else
    //     skcp->loop = ev_default_loop(0);
    // #endif

    skcp->notify_input_watcher = (ev_async *)SKCP_ALLOC(sizeof(ev_async));
    skcp->notify_input_watcher->data = skcp;
    ev_async_init(skcp->notify_input_watcher, notify_input_cb);
    ev_async_start(skcp->loop, skcp->notify_input_watcher);

    //     skcp->r_watcher = malloc(sizeof(struct ev_io));
    //     skcp->r_watcher->data = skcp;
    //     ev_io_init(skcp->r_watcher, read_cb, skcp->fd, EV_READ);
    //     ev_io_start(skcp->loop, skcp->r_watcher);

    // ev_run(skcp->loop, 0);

    return skcp;
}

void skcp_free(skcp_t *skcp) {
    if (!skcp) {
        return;
    }

    for (uint i = 0; i < skcp->conf->engine_cnt; i++) {
        skcp_engine_free(skcp->engine_list[i]);
    }

    for (uint i = 0; i < skcp->conf->io_cnt; i++) {
        skcp_io_free(skcp->io_list[i]);
    }

    if (skcp->in_mq) {
        skcp_free_queue(skcp->in_mq, skcp_del_msg);
        skcp->in_mq = NULL;
    }

    if (skcp->conn_slots) {
        for (uint32_t i = 0; i < skcp->conn_slots->remain_idx; i++) {
            uint32_t cid = skcp->conn_slots->remain_id_stack[i];
            skcp_close_conn(skcp, cid);
        }
        skcp_free_conn_slots(skcp->conn_slots);
    }

    SKCP_FREEIF(skcp);
}

int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, size_t len) {
    skcp_conn_t *conn = skcp_get_conn(skcp->conn_slots, cid);
    if (!conn || conn->status != SKCP_CONN_ST_ON) {
        return -1;
    }

    skcp_msg_t *msg = NULL;
    uint idx = skcp_route_engine(cid, skcp->conf->engine_cnt);
    // skcp_engine_t *engine = route_to_engine(skcp, cid);
    SKCP_INIT_ENGINE_MSG(msg, SKCP_MSG_TYPE_SEND, cid, buf, len, skcp);
    if (skcp_engine_feed(skcp->engine_list[idx], msg) != SKCP_OK) {
        return -1;
    }

    return len;
}

uint32_t skcp_create_conn(skcp_t *skcp) {
    skcp_conn_t *conn = skcp_init_conn(skcp->conn_slots, skcp->conf, 0, skcp->io_list, skcp->conf->io_cnt);
    if (!conn) {
        return 0;
    }
    conn->skcp = skcp;
    uint idx = skcp_route_engine(conn->id, skcp->conf->engine_cnt);
    skcp_engine_reg_conn(skcp->engine_list[idx], conn);
    return conn->id;
}

void skcp_close_conn(skcp_t *skcp, uint32_t cid) {
    uint idx = skcp_route_engine(cid, skcp->conf->engine_cnt);
    skcp_msg_t *msg = NULL;
    SKCP_INIT_ENGINE_MSG(msg, SKCP_MSG_TYPE_CLOSE_MANUAL, cid, NULL, 0, NULL);
    skcp_engine_feed(skcp->engine_list[idx], msg);
}

int skcp_req_cid(skcp_t *skcp, const char *ticket, int len) {
    // if (skcp->mode != SKCP_MODE_CLI) {
    //     return -1;
    // }

    int out_len = 0;
    char *buf = encode_cmd(0, SKCP_CMD_REQ_CID, ticket, len, &out_len);
    if (skcp_io_send(skcp->io_list[0], buf, len, skcp->io_list[0]->serv_addr) < 0) {
        return SKCP_ERR;
    }

    return SKCP_OK;
}
