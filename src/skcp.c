#include "skcp.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <openssl/aes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if !defined(_IF_NULL)
#define _IF_NULL(v) if (NULL == (v))
#endif  // _IF_NULL

#if !defined(_ALLOC)
#define _ALLOC(v_type, v_element_size) (v_type *)calloc(1, (v_element_size))
#endif  // _ALLOC

#if !defined(_ALLOC_IF)
#define _ALLOC_IF(v_el, v_type, v_el_size)     \
    (v_el) = (v_type *)calloc(1, (v_el_size)); \
    if (NULL == (v_el))
#endif  // _ALLOC_IF

#if !defined(_ALLOC_OR_EXIT)
#define _ALLOC_OR_EXIT(v_el, v_type, v_el_size) \
    _ALLOC_IF(v_el, v_type, v_el_size) {        \
        perror("alloc error");                  \
        exit(1);                                \
    }
#endif  // _ALLOC_OR_EXIT

#if !defined(_NEW_IF)
#define _NEW_IF(v_el, v_type, v_el_size) v_type *_ALLOC_IF(v_el, v_type, v_el_size)
#endif  // _NEW_IF

#if !defined(_NEW_OR_EXIT)
#define _NEW_OR_EXIT(v_el, v_type, v_el_size) \
    _NEW_IF(v_el, v_type, v_el_size) {        \
        perror("alloc error");                \
        exit(1);                              \
    }
#endif  // _NEW_OR_EXIT

#if !defined(_FREE_IF)
#define _FREE_IF(p)   \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0)
#endif  // _FREE_IF

#if !defined(_IF_STR_EMPTY)
#define _IF_STR_EMPTY(v) if ((v) != NULL && strlen((v)) > 0)
#endif  // _IF_STR_EMPTY

#if !defined(_LOG)
#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)
#endif  // _LOG

#define SKCP_MAX_CID (2 ^ 32)

/* -------------------------------------------------------------------------- */
/*                               common function                              */
/* -------------------------------------------------------------------------- */
inline static uint64_t getmillisecond() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

inline static uint32_t getms() { return (uint32_t)(getmillisecond() & 0xfffffffful); }

// inline static void build_iv(char *iv, const uint32_t cid, const char *ticket) {
//     char iv_str[SKCP_IV_LEN + 1] = {0};
//     snprintf(iv_str, SKCP_IV_LEN + 1, "%u", cid);
//     for (size_t i = strlen(iv_str); i < SKCP_IV_LEN && i < SKCP_TICKET_LEN; i++) {
//         iv_str[i] = ticket[i];
//     }
// }

/* -------------------------------------------------------------------------- */
/*                                   cipher                                   */
/* -------------------------------------------------------------------------- */

inline static unsigned char *str2hex(const char *str) {
    unsigned char *ret = NULL;
    int str_len = strlen(str);
    int i = 0;
    assert((str_len % 2) == 0);
    ret = malloc(str_len / 2);
    for (i = 0; i < str_len; i = i + 2) {
        sscanf(str + i, "%2hhx", &ret[i / 2]);
    }
    return ret;
}

inline static char *cipher_padding(const char *buf, int size, int *final_size) {
    char *ret = NULL;
    int pidding_size = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    int i;
    *final_size = size + pidding_size;
    ret = (char *)malloc(size + pidding_size);
    memcpy(ret, buf, size);
    if (pidding_size != 0) {
        for (i = size; i < (size + pidding_size); i++) {
            ret[i] = 0;
        }
    }
    return ret;
}

inline static void aes_cbc_encrpyt(const char *raw_buf, char **encrpy_buf, int len, const char *key, const char *iv) {
    AES_KEY aes_key;
    unsigned char *skey = str2hex(key);
    unsigned char *siv = str2hex(iv);
    AES_set_encrypt_key(skey, 128, &aes_key);
    AES_cbc_encrypt((unsigned char *)raw_buf, (unsigned char *)*encrpy_buf, len, &aes_key, siv, AES_ENCRYPT);
    _FREE_IF(skey);
    _FREE_IF(siv);
}
inline static void aes_cbc_decrypt(const char *raw_buf, char **encrpy_buf, int len, const char *key, const char *iv) {
    AES_KEY aes_key;
    unsigned char *skey = str2hex(key);
    unsigned char *siv = str2hex(iv);
    AES_set_decrypt_key(skey, 128, &aes_key);
    AES_cbc_encrypt((unsigned char *)raw_buf, (unsigned char *)*encrpy_buf, len, &aes_key, siv, AES_DECRYPT);
    _FREE_IF(skey);
    _FREE_IF(siv);
}
inline static char *aes_encrypt(const char *key, const char *iv, const char *in, int in_len, int *out_len) {
    int padding_size = in_len;
    char *after_padding_buf = (char *)in;
    if (in_len % 16 != 0) {
        after_padding_buf = cipher_padding(in, in_len, &padding_size);
    }
    *out_len = padding_size;

    char *out_buf = malloc(padding_size);
    memset(out_buf, 0, padding_size);
    aes_cbc_encrpyt(after_padding_buf, &out_buf, padding_size, key, iv);
    if (in_len % 16 != 0) {
        _FREE_IF(after_padding_buf);
    }
    return out_buf;
}

static char *aes_decrypt(const char *key, const char *iv, const char *in, int in_len, int *out_len) {
    int padding_size = in_len;
    char *after_padding_buf = (char *)in;
    if (in_len % 16 != 0) {
        after_padding_buf = cipher_padding(in, in_len, &padding_size);
    }
    *out_len = padding_size;

    char *out_buf = malloc(padding_size);
    memset(out_buf, 0, padding_size);
    aes_cbc_decrypt(after_padding_buf, &out_buf, padding_size, key, iv);
    if (in_len % 16 != 0) {
        _FREE_IF(after_padding_buf);
    }
    return out_buf;
}

/* -------------------------------------------------------------------------- */
/*                                  protocol                                  */
/* -------------------------------------------------------------------------- */

/**
skcp format: cmd(char)cid(uint32)ticket(char[32])remain_length(uint32)payload
skcp head length: 1+4+32+4 = 41B
ether header and crc length: 18B
IP header length: 20B
UDP header length: 8B
KCP header length: 24B
total = skcp_header + kcp_header + kcp_MTU
total = 1500
total_16 = 1488
kcp_MTU = 1488 - 41 = 1447
**/

#define SKCP_HEADER_LEN 41
#define SKCP_CMD_DATA_UDP 'U'
#define SKCP_CMD_DATA_KCP 'K'
#define SKCP_CMD_CTRL_REQ_CID 'R'
#define SKCP_CMD_CTRL_ACK_CID 'A'

// #define SKCP_MAX_UDP_PAYLOAD_LEN (SKCP_MAX_RW_BUF_LEN - SKCP_HEADER_LEN)
// #define SKCP_MAX_KCP_PAYLOAD_LEN (SKCP_MAX_UDP_PAYLOAD_LEN - 24)
#define SKCP_MAX_RW_BUF_LEN_16 (floor(SKCP_MAX_RW_BUF_LEN / 16.0) * 16)
#define KCP_MAX_MTU floor((SKCP_MAX_RW_BUF_LEN_16 - SKCP_HEADER_LEN))

typedef struct skcp_pkt_s {
    char cmd;
    uint32_t cid;
    char ticket[SKCP_TICKET_LEN];
    uint32_t remain_len;
    char payload[SKCP_MAX_RW_BUF_LEN];
} skcp_pkt_t;

#define BUILD_SKCP_PKT(v_el, v_cmd, v_cid, v_remain_len, v_ticket_p, v_paload) \
    assert((v_remain_len) <= SKCP_MAX_RW_BUF_LEN);                             \
    skcp_pkt_t v_el = {                                                        \
        .cmd = (v_cmd),                                                        \
        .cid = (v_cid),                                                        \
        .remain_len = (v_remain_len),                                          \
    };                                                                         \
    if ((v_ticket_p)) memcpy((v_el).ticket, (v_ticket_p), SKCP_TICKET_LEN);    \
    if ((v_remain_len) > 0) memcpy((v_el).payload, (v_paload), (v_remain_len))

inline static int skcp_pack(skcp_pkt_t *pkt, char *buf, int len) {
    int total_len = SKCP_HEADER_LEN + pkt->remain_len;
    if (!pkt || len < total_len || SKCP_MAX_RW_BUF_LEN < total_len) {
        return 0;
    }
    *buf = pkt->cmd;
    uint32_t n_cid = htonl(pkt->cid);
    memcpy(buf + 1, &n_cid, 4);
    memcpy(buf + 5, pkt->ticket, SKCP_TICKET_LEN);
    uint32_t n_remain_len = htonl(pkt->remain_len);
    memcpy(buf + 37, &n_remain_len, 4);
    memcpy(buf + 41, pkt->payload, pkt->remain_len);
    assert(len > SKCP_HEADER_LEN + pkt->remain_len);
    return SKCP_HEADER_LEN + pkt->remain_len;
}

inline static bool skcp_unpack(char *buf, int len, skcp_pkt_t *pkt) {
    if (!buf || len < SKCP_HEADER_LEN || !pkt) {
        return false;
    }
    pkt->cmd = *buf;
    if (pkt->cmd != SKCP_CMD_DATA_UDP && pkt->cmd != SKCP_CMD_DATA_KCP && pkt->cmd != SKCP_CMD_CTRL_REQ_CID &&
        pkt->cmd != SKCP_CMD_CTRL_ACK_CID) {
        return false;
    }
    pkt->cid = ntohl(*(uint32_t *)(buf + 1));
    memcpy(pkt->ticket, buf + 5, SKCP_TICKET_LEN);
    pkt->remain_len = ntohl(*(uint32_t *)(buf + 37));
    if (pkt->remain_len > len - SKCP_HEADER_LEN) {
        return false;
    }
    if (pkt->remain_len > 0) {
        memcpy(pkt->payload, buf + 41, pkt->remain_len);
    }
    return true;
}

/* -------------------------------------------------------------------------- */
/*                                    skcp                                    */
/* -------------------------------------------------------------------------- */

/* ------------------------------- definitions ------------------------------- */
static char *def_iv = "9586cda28238ab24c8a484df6e355f91";

/* ------------------------------- private api ------------------------------ */

inline static uint32_t gen_cid(skcp_t *skcp) {
    skcp->cid_seed++;
    if (skcp->cid_seed > SKCP_MAX_CID) {
        skcp->cid_seed = 1;
    }
    return skcp->cid_seed;
}

static int init_cli_network(skcp_t *skcp) {
    // 设置客户端
    // 创建socket对象
    skcp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    // 设置为非阻塞
    if (-1 == fcntl(skcp->fd, F_SETFL, fcntl(skcp->fd, F_GETFL) | O_NONBLOCK)) {
        // _LOG("error fcntl");
        close(skcp->fd);
        return -1;
    }

    skcp->servaddr.sin_family = AF_INET;
    skcp->servaddr.sin_port = htons(skcp->conf->port);
    skcp->servaddr.sin_addr.s_addr = inet_addr(skcp->conf->addr);

    // _LOG("kcp client start ok. fd: %d addr: %s port: %u", skcp->fd, skcp->conf->addr, skcp->conf->port);

    return 0;
}

static int init_serv_network(skcp_t *skcp) {
    // 设置服务端
    skcp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == skcp->fd) {
        // _LOG("start kcp server socket error");
        return -1;
    }
    // 设置为非阻塞
    if (-1 == fcntl(skcp->fd, F_SETFL, fcntl(skcp->fd, F_GETFL) | O_NONBLOCK)) {
        perror("setnonblock error");
        close(skcp->fd);
        return -1;
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (NULL == skcp->conf->addr) {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(skcp->conf->addr);
    }
    servaddr.sin_port = htons(skcp->conf->port);

    if (-1 == bind(skcp->fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        // _LOG("bind error when start kcp server");
        close(skcp->fd);
        return -1;
    }

    // _LOG("kcp server start ok. fd: %d addr: %s port: %u", skcp->fd, skcp->conf->addr, skcp->conf->port);

    return 0;
}

static int udp_send(skcp_t *skcp, skcp_pkt_t *pkt, struct sockaddr_in target_addr) {
    char buf[SKCP_MAX_RW_BUF_LEN] = {0};
    int len = skcp_pack(pkt, buf, sizeof(buf));
    if (len <= 0) {
        _LOG("skcp pack error");
        return -1;
    }

    // encrypt
    char *cipher_txt = buf;
    int cipher_txt_len = len;
    _IF_STR_EMPTY(skcp->key) {
        cipher_txt = aes_encrypt(skcp->key, def_iv, buf, len, &cipher_txt_len);  // TODO: 性能优化
    }
    int wlen = sendto(skcp->fd, cipher_txt, cipher_txt_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
    _IF_STR_EMPTY(skcp->key) { _FREE_IF(cipher_txt); }
    if (wlen <= 0) {
        _LOG("udp send error %s", strerror(errno));
        return -1;
    }
    assert(cipher_txt_len == wlen);
    return wlen;
}

static int udp_recv(skcp_t *skcp, skcp_pkt_t *pkt, struct sockaddr_in *from_addr) {
    char raw[SKCP_MAX_RW_BUF_LEN] = {0};
    socklen_t addr_len = sizeof(*from_addr);
    int rlen = recvfrom(skcp->fd, raw, sizeof(raw), 0, (struct sockaddr *)from_addr, &addr_len);
    if (rlen <= 0) {
        _LOG("udp recv error %s", strerror(errno));
        return -1;
    }

    // decrypt
    char *plain_txt = raw;
    int plain_txt_len = rlen;
    _IF_STR_EMPTY(skcp->key) { plain_txt = aes_decrypt(skcp->key, def_iv, raw, rlen, &plain_txt_len); }

    int rt = -1;
    if (skcp_unpack(plain_txt, plain_txt_len, pkt)) {
        rt = plain_txt_len;
    }
    _IF_STR_EMPTY(skcp->key) { _FREE_IF(plain_txt); }
    return rt;
}

static int kcp_output(const char *buf, int len, struct IKCPCB *kcp, void *user) {
    skcp_conn_t *conn = (skcp_conn_t *)user;

    // if (conn->skcp->mode == SKCP_MODE_SERV && ikcp_waitsnd(kcp) > 200) {  // TODO: for test
    //     _LOG("kcp_output cid: %u", kcp->conv);
    // }
    // assert(len <= SKCP_MAX_UDP_PAYLOAD_LEN);

    char *t = conn->ticket;
    // _LOG("kcp_output ticket:%s", t);
    BUILD_SKCP_PKT(pkt, SKCP_CMD_DATA_KCP, conn->id, len, t, buf);

    int rt = udp_send(conn->skcp, &pkt, conn->target_addr);
    if (rt > 0) {
        conn->last_w_tm = getmillisecond();
    }

    return rt;
}

static void kcp_update_cb(struct ev_loop *loop, ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        // _LOG("kcp update got invalid event");
        return;
    }
    skcp_conn_t *conn = (skcp_conn_t *)(watcher->data);
    ikcp_update(conn->kcp, getms());

    // check timeout
    uint64_t now = getmillisecond();
    if (now - conn->last_r_tm > conn->skcp->conf->r_keepalive * 1000) {
        // _LOG("timeout cid: %u", conn->id);
        skcp_close_conn(conn->skcp, conn->id);
        return;
    }
}

/* ------------------------------- connection ------------------------------- */
inline static skcp_conn_t *get_conn(skcp_conn_t *conn_ht, uint32_t sid) {
    skcp_conn_t *conn = NULL;
    HASH_FIND_INT(conn_ht, &sid, conn);
    return conn;
}

static skcp_conn_t *init_conn(skcp_t *skcp, int32_t cid, char *ticket, struct sockaddr_in target_addr,
                              void *user_data) {
    assert(skcp);
    _NEW_OR_EXIT(conn, skcp_conn_t, sizeof(skcp_conn_t));
    conn->last_r_tm = conn->last_w_tm = getmillisecond();
    conn->status = SKCP_CONN_ST_ON;  // SKCP_CONN_ST_READY;
    conn->skcp = skcp;
    conn->user_data = user_data;
    conn->id = cid;
    conn->target_addr = target_addr;
    memcpy(conn->ticket, ticket, SKCP_TICKET_LEN);
    // memcpy(conn->iv, iv_str, SKCP_IV_LEN);
    HASH_ADD_INT(skcp->conns, id, conn);

    ikcpcb *kcp = ikcp_create(cid, conn);
    skcp_conf_t *conf = skcp->conf;
    kcp->output = kcp_output;
    ikcp_wndsize(kcp, conf->sndwnd, conf->rcvwnd);
    ikcp_nodelay(kcp, conf->nodelay, conf->interval, conf->nodelay, conf->nc);
    ikcp_setmtu(kcp, conf->mtu);

    // kcp->rx_minrto = 10;  // TODO: for test

    conn->kcp = kcp;

    // 设置kcp定时循环
    conn->kcp_update_watcher = malloc(sizeof(ev_timer));
    double kcp_interval = conf->interval / 1000.0;
    conn->kcp_update_watcher->data = conn;
    ev_init(conn->kcp_update_watcher, kcp_update_cb);
    ev_timer_set(conn->kcp_update_watcher, kcp_interval, kcp_interval);
    ev_timer_start(skcp->loop, conn->kcp_update_watcher);

    return conn;
}

static void free_conn(skcp_t *skcp, skcp_conn_t *conn) {
    if (!skcp || !conn) {
        return;
    }

    if (skcp->conns) {
        HASH_DEL(skcp->conns, conn);
    }

    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }

    if (conn->kcp_update_watcher) {
        ev_timer_stop(skcp->loop, conn->kcp_update_watcher);
        _FREE_IF(conn->kcp_update_watcher);
    }

    conn->status = SKCP_CONN_ST_OFF;
    conn->id = 0;
    conn->user_data = NULL;

    _FREE_IF(conn);
}

static void on_recv_req_sid_pkt(skcp_t *skcp, skcp_pkt_t *pkt, struct sockaddr_in addr) {
    uint32_t cid = gen_cid(skcp);
    // create connection in server
    skcp_conn_t *conn = init_conn(skcp, cid, pkt->ticket, addr, NULL);
    if (!conn) {
        return;
    }
    // send ack sid cmd to client
    char *t = pkt->ticket;
    BUILD_SKCP_PKT(ack_pkt, SKCP_CMD_CTRL_ACK_CID, cid, 0, t, "");
    if (udp_send(skcp, &ack_pkt, addr) <= 0) {
        return;
    }

    skcp->conf->on_accept(skcp, conn->id);
}

static void on_recv_ack_sid_pkt(skcp_t *skcp, skcp_pkt_t *pkt, struct sockaddr_in addr) {
    if (pkt->cid <= 0) {
        _LOG("invalid sid in ack sid cmd");
        return;
    }

    // create connection in client
    skcp_conn_t *conn = init_conn(skcp, pkt->cid, pkt->ticket, addr, NULL);
    if (!conn) {
        return;
    }

    skcp->conf->on_recv_cid(skcp, conn->id);
}

static void on_recv_kcp_pkt(skcp_t *skcp, skcp_pkt_t *pkt, struct sockaddr_in addr) {
    // check kcp header and cid
    if (pkt->remain_len < 24) {
        _LOG("invalid len in kcp recv");
        return;
    }
    uint32_t conv = ikcp_getconv(pkt->payload);
    if (conv <= 0 || pkt->cid != conv) {
        _LOG("sid error in kcp recv conv: %u sid: %u", conv, pkt->cid);
        return;
    }
    skcp_conn_t *conn = get_conn(skcp->conns, pkt->cid);
    if (conn == NULL) {
        // _LOG("invalid connection in kcp recv %u", pkt->cid);
        return;
    }
    // feed data to kcp
    ikcp_input(conn->kcp, pkt->payload, pkt->remain_len);
    ikcp_update(conn->kcp, getms());
    // read data from kcp
    int peeksize = ikcp_peeksize(conn->kcp);
    if (peeksize <= 0) {
        return;
    }
    _NEW_OR_EXIT(recv_buf, char, peeksize);
    // 返回-1表示数据还没有收完数据，-3表示接受buf太小
    int recv_len = ikcp_recv(conn->kcp, recv_buf, peeksize);
    if (recv_len > 0) {
        ikcp_update(conn->kcp, getms());
        conn->last_r_tm = getmillisecond();
        skcp->conf->on_recv_data(skcp, conn->id, recv_buf, recv_len);
    }
    _FREE_IF(recv_buf);
}

static void on_recv_udp_pkt(skcp_t *skcp, skcp_pkt_t *pkt, struct sockaddr_in addr) {
    // TODO:
    _LOG("recv udp data");
}

static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        // _LOG("read_cb got invalid event");
        return;
    }
    skcp_t *skcp = (skcp_t *)(watcher->data);

    struct sockaddr_in from_addr;
    skcp_pkt_t pkt;
    bzero(&pkt, sizeof(skcp_pkt_t));  // TODO: for test
    int rlen = udp_recv(skcp, &pkt, &from_addr);
    if (rlen < 0) {
        return;
    }

    // auth ticket
    if (skcp->conf->on_check_ticket(skcp, pkt.ticket, SKCP_TICKET_LEN) != 0) {
        _LOG("ticket error");
        return;
    }
    if (pkt.cmd == SKCP_CMD_CTRL_REQ_CID) {
        // server mode only
        if (skcp->mode != SKCP_MODE_SERV) {
            _LOG("receive request cid cmd only in server mode");
            return;
        }
        on_recv_req_sid_pkt(skcp, &pkt, from_addr);
    } else if (pkt.cmd == SKCP_CMD_CTRL_ACK_CID) {
        // client mode only
        if (skcp->mode != SKCP_MODE_CLI) {
            _LOG("receive ack cid cmd only in client mode");
            return;
        }
        on_recv_ack_sid_pkt(skcp, &pkt, from_addr);
    } else if (pkt.cmd == SKCP_CMD_DATA_KCP) {
        on_recv_kcp_pkt(skcp, &pkt, from_addr);
    } else if (pkt.cmd == SKCP_CMD_DATA_UDP) {
        on_recv_udp_pkt(skcp, &pkt, from_addr);
    } else {
        _LOG("invalid protocol cmd");
        return;
    }
}

/* ------------------------------- public api ------------------------------- */

int skcp_req_cid(skcp_t *skcp, const char *ticket, int len) {
    if (skcp->mode != SKCP_MODE_CLI || len < SKCP_TICKET_LEN) {
        return -1;
    }

    BUILD_SKCP_PKT(pkt, SKCP_CMD_CTRL_REQ_CID, 0, 0, ticket, "");
    return udp_send(skcp, &pkt, skcp->servaddr);
}

int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, int len) {
    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn || !buf || len <= 0 || conn->status != SKCP_CONN_ST_ON) {
        return -1;
    }

    int rt = ikcp_send(conn->kcp, buf, len);
    if (rt < 0) {
        // 发送失败
        return -1;
    }
    ikcp_update(conn->kcp, getms());
    return rt;

    // int times = len / SKCP_MAX_KCP_PAYLOAD_LEN;
    // if ((len % SKCP_MAX_KCP_PAYLOAD_LEN) > 0) {
    //     times++;
    // }

    // int wlen = 0;
    // for (size_t i = 0; i < times; i++) {
    //     int rt = ikcp_send(conn->kcp, buf, len);
    //     if (rt < 0) {
    //         // 发送失败
    //         return -1;
    //     }
    //     wlen += rt;
    //     ikcp_update(conn->kcp, getms());
    //     buf += SKCP_MAX_KCP_PAYLOAD_LEN;
    //     len -= SKCP_MAX_KCP_PAYLOAD_LEN;
    // }

    // return wlen;
}

skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid) {
    if (!skcp || !skcp->conns || cid <= 0) {
        return NULL;
    }
    skcp_conn_t *conn = NULL;
    HASH_FIND_INT(skcp->conns, &cid, conn);
    return conn;
}

void skcp_close_conn(skcp_t *skcp, uint32_t cid) {
    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        return;
    }
    // _LOG("skcp_close_conn cid: %u", cid);
    skcp->conf->on_close(skcp, cid);

    free_conn(skcp, conn);
}

skcp_t *skcp_init(skcp_conf_t *conf, struct ev_loop *loop, void *user_data, SKCP_MODE mode) {
    if (!conf || !loop) {
        return NULL;
    }

    // skcp_t *skcp = (skcp_t *)_ALLOC(sizeof(skcp_t));
    _NEW_OR_EXIT(skcp, skcp_t, sizeof(skcp_t));
    skcp->conf = conf;
    skcp->mode = mode;
    skcp->user_data = user_data;
    skcp->loop = loop;
    skcp->conns = NULL;
    if (strlen(conf->key) > 0) {
        skcp->key = conf->key;
    }
    skcp->cid_seed = 0;
    if (conf->mtu <= 0 || conf->mtu > KCP_MAX_MTU) {
        conf->mtu = KCP_MAX_MTU;
    }
    _LOG("%f kcp mtu %d", SKCP_MAX_RW_BUF_LEN_16, conf->mtu);

    // setup network
    if (mode == SKCP_MODE_CLI) {
        if (init_cli_network(skcp) != 0) {
            _FREE_IF(skcp);
            return NULL;
        }
    } else {
        if (init_serv_network(skcp) != 0) {
            _FREE_IF(skcp);
            return NULL;
        }
    }

    // setup libev
    // 设置读事件循环
    skcp->r_watcher = malloc(sizeof(struct ev_io));
    skcp->r_watcher->data = skcp;
    ev_io_init(skcp->r_watcher, read_cb, skcp->fd, EV_READ);
    ev_io_start(skcp->loop, skcp->r_watcher);

    return skcp;
}

void skcp_free(skcp_t *skcp) {
    if (!skcp) {
        return;
    }

    if (skcp->r_watcher) {
        ev_io_stop(skcp->loop, skcp->r_watcher);
        _FREE_IF(skcp->r_watcher);
    }

    if (skcp->fd) {
        close(skcp->fd);
        skcp->fd = 0;
    }

    if (skcp->conns) {
        skcp_conn_t *conn, *tmp;
        HASH_ITER(hh, skcp->conns, conn, tmp) {
            HASH_DEL(skcp->conns, conn);
            skcp_close_conn(skcp, conn->id);
        }
        skcp->conns = NULL;
    }

    skcp->conf = NULL;
    skcp->user_data = NULL;

    _FREE_IF(skcp);
}
