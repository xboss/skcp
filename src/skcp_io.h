#ifndef _SKCP_IO_H
#define _SKCP_IO_H

#include <arpa/inet.h>
#include <pthread.h>

#include "skcp_queue.h"

#define SKCP_IO_MODE_SERVER 1
#define SKCP_IO_MODE_CLIENT 2

// #define SKCP_IO_MSG_TYPE_DATA 0x1
// #define SKCP_IO_MSG_TYPE_UDP 0x2

// #define SKCP_IO_INIT_MSG(_v_msg, _v_type, _v_buf, _v_buf_len, _v_user_data)           \
//     do {                                                                              \
//         skcp_io_msg_t *(_v_msg) = (skcp_io_msg_t *)SKCP_ALLOC(sizeof(skcp_io_msg_t)); \
//         (_v_msg)->type = (_v_type);                                                   \
//         (_v_msg)->buf_len = (_v_buf_len);                                             \
//         (_v_msg)->buf = (char *)SKCP_ALLOC((_v_buf_len));                             \
//         memcpy((_v_msg)->buf, (_v_buf), (_v_buf_len));                                \
//         (_v_msg)->user_data = (_v_user_data);                                         \
//     } while (0)

// #define SKCP_IO_FREE_MSG(_v_msg)            \
//     do {                                    \
//         if ((_v_msg)) {                     \
//             (_v_msg)->buf_len = 0;          \
//             if ((_v_msg)->buf) {            \
//                 SKCP_FREEIF((_v_msg)->buf); \
//             }                               \
//             SKCP_FREEIF((_v_msg));          \
//         }                                   \
//     } while (0)

// typedef struct {
//     u_char type;
//     char *buf;
//     size_t buf_len;
//     struct sockaddr_in dst_addr;
//     void *user_data;
// } skcp_io_msg_t;

// typedef void (*notify_fn_t)(skcp_queue_t *);

// typedef void (*recv_fn_t)(const char *buf, size_t len);

typedef struct skcp_io_s {
    int mode;  // 1: server; 2: client;
    char *addr;
    uint16_t port;
    int fd;
    struct sockaddr_in serv_addr;
    // struct sockaddr_in dst_addr;
    // char *key;
    // int skcp_tid;

    struct ev_loop *loop;
    struct ev_io *r_watcher;
    // struct ev_io *r_notify_watcher;
    ev_async *notify_input_watcher;
    // struct ev_timer *tick_watcher;
    // int tick;  // millsec

    // recv_fn_t on_recv;

    skcp_queue_t *in_mq;
    skcp_conf_t *conf;
    // skcp_queue_t *out_mq;

    // int mq_notify_fd[2];
    // notify_fn_t notify_fn;
    // int notify_io_fd[2];

    pthread_t tid;
    void (*handler)(skcp_msg_t *);
    // int shutdown;  // 1: shutdown; 0: not shutdown;
    void *user_data;
} skcp_io_t;

skcp_io_t *skcp_io_init(skcp_conf_t *conf, void (*handler)(skcp_msg_t *), void *user_data);
void skcp_io_free(skcp_io_t *io);
int skcp_io_send(skcp_io_t *io, const char *buf, size_t len, struct sockaddr_in dst_addr);
// char *skcp_io_recv(skcp_io_t *io, int *len);

// int skcp_io_reg_notify(struct ev_loop *loop, void (*read_cb)(struct ev_loop *, struct ev_io *, int), void *ud);
// int skcp_io_notify(skcp_io_t *io, struct ev_loop *loop, struct ev_io *r_watcher,
//                    void (*read_cb)(struct ev_loop *, struct ev_io *, int));
// char *skcp_io_block_recv(skcp_io_t *io, int *len);
#endif  // SKCP_IO_H