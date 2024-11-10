#ifndef _SKCP_H
#define _SKCP_H

#include <arpa/inet.h>

#include "ikcp.h"
#include "uthash.h"

#define SKCP_CIPHER_KEY_LEN 16
#if !defined(INET_ADDRSTRLEN)
#define INET_ADDRSTRLEN 16
#endif  // INET_ADDRSTRLEN

typedef enum { SKCP_CONN_ST_ON = 1, SKCP_CONN_ST_OFF } SKCP_CONN_ST;
typedef enum { SKCP_MODE_SERV = 1, SKCP_MODE_CLI } SKCP_MODE;

typedef struct skcp_conn_s skcp_conn_t;
typedef struct skcp_s skcp_t;

typedef struct skcp_conf_s {
    int kcp_mtu;
    int kcp_nodelay;
    int kcp_resend;
    int kcp_nc;
    int kcp_sndwnd;
    int kcp_rcvwnd;
    int kcp_interval; /* millisecond */
    SKCP_MODE mode;
    char key[SKCP_CIPHER_KEY_LEN + 1];
    int (*skcp_output_cb)(skcp_t *skcp, uint32_t cid, const char *buf, int len);
} skcp_conf_t;

struct skcp_conn_s {
    uint32_t id;
    skcp_t *skcp;
    ikcpcb *kcp;
    SKCP_CONN_ST status;
    /* struct sockaddr_in target_sockaddr;
    int ex; */
    void *ud;
    UT_hash_handle hh;
};

struct skcp_s {
    int fd;
    skcp_conf_t conf;
    skcp_conn_t *conn_tb;
    /* struct sockaddr_in servaddr; */
    char *cipher_buf;
    /* struct sockaddr_in target_sockaddr; */
    void *user_data;
};

skcp_t *skcp_init(skcp_conf_t *conf, void *user_data);
void skcp_free(skcp_t *skcp);
int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, int len);
void skcp_close_conn(skcp_t *skcp, uint32_t cid);
skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid);
void skcp_update(skcp_t *skcp, uint32_t cid);
uint32_t skcp_input(skcp_t *skcp, const char *buf, int len);
skcp_conn_t *skcp_init_conn(skcp_t *skcp, int32_t cid /* , struct sockaddr_in target_addr */);
int skcp_rcv(skcp_t *skcp, int32_t cid, char *buf, int len);
int skcp_encrypt(const char *key, const char *in, int in_len, char **out, int *out_len);
int skcp_decrypt(const char *key, const char *in, int in_len, char **out, int *out_len);
uint32_t skcp_get_cid(const char* buf);

#endif