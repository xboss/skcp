#include "skcp_io.h"

#include <fcntl.h>
#include <openssl/aes.h>
#include <unistd.h>

#include "string.h"

// #define SKCP_IO_R_BUF_SZ 1500

// typedef struct {
//     struct sockaddr_in dst_addr;
//     char *buf;
//     size_t buf_len;
// } skcp_io_msg_t;

/* -------------------------------------------------------------------------- */
/*                                   cipher                                   */
/* -------------------------------------------------------------------------- */
static char *def_iv = "9586cda28238ab24c8a484df6e355f90";

inline static unsigned char *str2hex(const char *str) {
    unsigned char *ret = NULL;
    int str_len = strlen(str);
    int i = 0;
    // assert((str_len % 2) == 0);
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
    SKCP_FREEIF(skey);
    SKCP_FREEIF(siv);
}
inline static void aes_cbc_decrypt(const char *raw_buf, char **encrpy_buf, int len, const char *key, const char *iv) {
    AES_KEY aes_key;
    unsigned char *skey = str2hex(key);
    unsigned char *siv = str2hex(iv);
    AES_set_decrypt_key(skey, 128, &aes_key);
    AES_cbc_encrypt((unsigned char *)raw_buf, (unsigned char *)*encrpy_buf, len, &aes_key, siv, AES_DECRYPT);
    SKCP_FREEIF(skey);
    SKCP_FREEIF(siv);
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
        SKCP_FREEIF(after_padding_buf);
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
        SKCP_FREEIF(after_padding_buf);
    }
    return out_buf;
}

/* -------------------------------------------------------------------------- */
/*                                   skcp io                                  */
/* -------------------------------------------------------------------------- */

static int init_cli_network(skcp_io_t *io) {
    // 设置客户端
    // 创建socket对象
    io->fd = socket(AF_INET, SOCK_DGRAM, 0);
    // 设置为非阻塞
    if (-1 == fcntl(io->fd, F_SETFL, fcntl(io->fd, F_GETFL) | O_NONBLOCK)) {
        // SKCP_LOG("error fcntl");
        close(io->fd);
        return -1;
    }
    // 设置reuseport
    int reuse = 1;
    setsockopt(io->fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&reuse, sizeof(int));

    io->serv_addr.sin_family = AF_INET;
    io->serv_addr.sin_port = htons(io->port);
    io->serv_addr.sin_addr.s_addr = inet_addr(io->addr);

    SKCP_LOG("io client start ok. fd: %d addr: %s port: %u", io->fd, io->addr, io->port);

    return 0;
}

static int init_serv_network(skcp_io_t *io) {
    // 设置服务端
    io->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == io->fd) {
        // SKCP_LOG("start kcp server socket error");
        return -1;
    }
    // 设置为非阻塞
    if (-1 == fcntl(io->fd, F_SETFL, fcntl(io->fd, F_GETFL) | O_NONBLOCK)) {
        perror("setnonblock error");
        close(io->fd);
        return -1;
    }
    // 设置reuseport
    int reuse = 1;
    setsockopt(io->fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&reuse, sizeof(int));

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (NULL == io->addr) {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(io->addr);
    }
    servaddr.sin_port = htons(io->port);

    if (-1 == bind(io->fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        // SKCP_LOG("bind error when start io server");
        close(io->fd);
        return -1;
    }

    io->serv_addr = servaddr;

    SKCP_LOG("io server start ok. fd: %d addr: %s port: %u", io->fd, io->addr, io->port);

    return 0;
}

inline static int udp_send(skcp_io_t *io, const char *buf, int len, struct sockaddr_in dst_addr) {
    if (!buf || len <= 0) {
        return -1;
    }

    int rt = -1;
    if (io->conf->key && strlen(io->conf->key) > 0) {
        // 加密
        char *cipher_buf = NULL;
        int cipher_buf_len = 0;
        cipher_buf = aes_encrypt(io->conf->key, def_iv, buf, len, &cipher_buf_len);
        rt = sendto(io->fd, cipher_buf, cipher_buf_len, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
        SKCP_FREEIF(cipher_buf);
    } else {
        rt = sendto(io->fd, buf, len, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    }

    // assert(rt > 0);
    if (rt < 0) {
        perror("udp send error");
    }

    return rt;
}

static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        return;
    }
    skcp_io_t *io = (skcp_io_t *)(watcher->data);
    SKCP_LOG("io read_cb %d", io->fd);

    char *raw_buf = (char *)SKCP_ALLOC(io->conf->r_buf_size);
    struct sockaddr_in cliaddr;
    socklen_t cliaddr_len = sizeof(cliaddr);
    int32_t bytes = recvfrom(io->fd, raw_buf, io->conf->r_buf_size, 0, (struct sockaddr *)&cliaddr, &cliaddr_len);
    if (-1 == bytes) {
        perror("read_cb recvfrom error");
        SKCP_FREEIF(raw_buf);
        return;
    }

    // skcp_msg_t *msg = (skcp_msg_t *)SKCP_ALLOC(sizeof(skcp_msg_t));
    // msg->buf_len = bytes;
    // memcpy(msg->buf, raw_buf, bytes);
    // skcp_push_queue(io->out_mq, msg);
    // SKCP_FREEIF(raw_buf);
    // notify_io_out_mq('R');

    // 解密
    char *plain_buf = raw_buf;
    int plain_len = bytes;
    if (io->conf->key && strlen(io->conf->key) > 0) {
        plain_buf = aes_decrypt(io->conf->key, def_iv, raw_buf, bytes, &plain_len);
        SKCP_FREEIF(raw_buf);
    }

    // TODO: create cid
    uint32_t cid = 0;
    skcp_decode32u((const char *)plain_buf, &cid);
    if (cid == 0) {
        // pure udp
        skcp_msg_t *msg = NULL;
        SKCP_INIT_IO_MSG(msg, SKCP_MSG_TYPE_UDP, cliaddr, plain_buf, plain_len, io->user_data);
        SKCP_FREEIF(plain_buf);
        io->handler(msg);
        SKCP_FREE_MSG(msg);
        // skcp_push_queue(io->out_mq, msg);
        // if (plain_len < SKCP_CMD_HEADER_LEN) {
        //     _FREEIF(plain_buf);
        //     return;
        // }
        // skcp_cmd_t *cmd = decode_cmd(plain_buf, plain_len);
        // _FREEIF(plain_buf);
        // if (!cmd) {
        //     // _LOG("decode_cmd error");
        //     return;
        // }
        // if (cmd->type == SKCP_CMD_REQ_CID) {
        //     on_req_cid_cmd(cmd, cliaddr);
        //     _FREEIF(cmd);
        //     return;
        // }
        // if (cmd->type == SKCP_CMD_REQ_CID_ACK) {
        //     on_req_cid_ack_cmd(cmd);
        //     _FREEIF(cmd);
        //     return;
        // }
        // _FREEIF(cmd);
        return;
    }

    // kcp protocol
    if (plain_len < 24) {
        SKCP_FREEIF(plain_buf);
        return;
    }

    skcp_msg_t *msg = NULL;
    SKCP_INIT_IO_MSG(msg, SKCP_MSG_TYPE_DATA, cliaddr, plain_buf, plain_len, io->user_data);
    SKCP_FREEIF(plain_buf);
    io->handler(msg);
    SKCP_FREE_MSG(msg);
}

static void *routine_fn(void *arg) {
    skcp_io_t *io = (skcp_io_t *)arg;
    ev_run(io->loop, 0);
    return NULL;
}

static void notify_input_cb(struct ev_loop *loop, struct ev_async *watcher, int revents) {
    skcp_io_t *io = (skcp_io_t *)watcher->data;
    SKCP_LOG("io notify_input_cb %d", io->fd);
    // send
    while (io->in_mq->size > 0) {
        skcp_msg_t *msg = (skcp_msg_t *)skcp_pop_queue(io->in_mq);
        udp_send(io, msg->buf, msg->buf_len, msg->dst_addr);
        SKCP_FREE_MSG(msg);
    }
}

/* ------------------------------- public api ------------------------------- */

skcp_io_t *skcp_io_init(skcp_conf_t *conf, void (*handler)(skcp_msg_t *), void *user_data) {
    if (!conf) {
        return NULL;
    }

    skcp_io_t *io = (skcp_io_t *)SKCP_ALLOC(sizeof(skcp_io_t));
    io->addr = conf->addr;
    io->port = conf->port;
    io->mode = conf->mode;
    io->conf = conf;
    io->handler = handler;
    io->user_data = user_data;
    // io->shutdown = 0;

    if (conf->mode == SKCP_IO_MODE_SERVER) {
        // server
        if (init_serv_network(io) != 0) {
            skcp_io_free(io);
            return NULL;
        }
    } else {
        // client
        if (init_cli_network(io) != 0) {
            skcp_io_free(io);
            return NULL;
        }
    }

    // io->loop = NULL;
#if (defined(__linux__) || defined(__linux))
    io->loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    io->loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    io->loop = ev_default_loop(0);
#endif

    io->in_mq = skcp_init_queue(-1);
    if (!io->in_mq) {
        skcp_io_free(io);
        return NULL;
    }

    io->notify_input_watcher = (ev_async *)SKCP_ALLOC(sizeof(ev_async));
    io->notify_input_watcher->data = io;
    ev_async_init(io->notify_input_watcher, notify_input_cb);
    ev_async_start(io->loop, io->notify_input_watcher);

    io->r_watcher = malloc(sizeof(struct ev_io));
    io->r_watcher->data = io;
    ev_io_init(io->r_watcher, read_cb, io->fd, EV_READ);
    ev_io_start(io->loop, io->r_watcher);

    // io->r_notify_watcher = malloc(sizeof(struct ev_io));
    // io->r_notify_watcher->data = io;
    // ev_io_init(io->r_notify_watcher, notify_cb, io->mq_notify_fd[0], EV_READ);
    // ev_io_start(io->loop, io->r_notify_watcher);

    // io->tick_watcher = malloc(sizeof(ev_timer));
    // double interval = io->tick / 1000.0;
    // io->tick_watcher->data = io;
    // ev_init(io->tick_watcher, tick_cb);
    // ev_timer_set(io->tick_watcher, 0, interval);
    // ev_timer_start(io->loop, io->tick_watcher);

    if (pthread_create(&io->tid, NULL, routine_fn, io)) {
        SKCP_LOG("start io thread error %s %d", io->addr, io->port);
        skcp_io_free(io);
        return NULL;
    }
    // io->shutdown = 0;

    SKCP_LOG("start io thread ok %d", io->fd);

    return io;
}

void skcp_io_free(skcp_io_t *io) {
    if (!io) {
        return;
    }

    if (io->loop) {
        // TODO: 可能需要feed event 和 free watcher
        ev_break(io->loop, EVBREAK_ALL);
        ev_loop_destroy(io->loop);
    }

    if (io->addr) {
        SKCP_FREEIF(io->addr);
    }

    // if (io->key) {
    //     SKCP_FREEIF(io->key);
    // }

    if (io->in_mq) {
        skcp_free_queue(io->in_mq, skcp_del_msg);
        io->in_mq = NULL;
    }

    // if (io->out_mq) {
    //     skcp_free_queue(io->out_mq, clean_out_mq);
    // }

    if (io->fd) {
        close(io->fd);
        io->fd = 0;
    }

    SKCP_FREEIF(io);
}

int skcp_io_send(skcp_io_t *io, const char *buf, size_t len, struct sockaddr_in dst_addr) {
    skcp_msg_t *msg = NULL;
    SKCP_INIT_IO_MSG(msg, SKCP_MSG_TYPE_DATA, dst_addr, buf, len, NULL);
    // (skcp_msg_t *)SKCP_ALLOC(sizeof(skcp_msg_t));
    // msg->buf_len = len;
    // msg->dst_addr = dst_addr;
    // msg->buf = (char *)SKCP_ALLOC(len);
    // memcpy(msg->buf, buf, len);
    if (skcp_push_queue(io->in_mq, msg) != 0) {
        SKCP_FREE_MSG(msg);
        return -1;
    }
    ev_async_send(io->loop, io->notify_input_watcher);
    return len;
}

// char *skcp_io_recv(skcp_io_t *io, int *len) {
//     *len = 0;
//     if (io->in_mq->size > 0) {
//         skcp_msg_t *msg = (skcp_msg_t *)skcp_pop_queue(io->out_mq);
//         *len = msg->buf_len;
//         char *buf = msg->buf;
//         SKCP_FREEIF(msg);
//         return buf;
//     }
//     return NULL;
// }

// int skcp_io_reg_notify(struct ev_loop *loop, void (*read_cb)(struct ev_loop *, struct ev_io *, int), void *ud) {
//     if (loop && read_cb) {
//         struct ev_io *n_r_watcher = malloc(sizeof(struct ev_io));
//         n_r_watcher->data = ud;
//         ev_io_init(n_r_watcher, read_cb, skcp_io_out_mq_notify_fd[0], EV_READ);
//         ev_io_start(loop, n_r_watcher);
//         return 0;
//     }
//     return -1;
// }

// char *skcp_io_block_recv(skcp_io_t *io, int *len) {
//     skcp_msg_t *msg = (skcp_msg_t *)skcp_pop_block_queue(io->out_mq);
//     *len = msg->buf_len;
//     char buf = msg->buf;
//     SKCP_FREEIF(msg);
//     return buf;
// }