#include "skcp_net.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int skcp_net_set_reuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) return _ERR;
    return _OK;
}

int skcp_net_set_nonblocking(int fd) {
    int flag = fcntl(fd, F_GETFL, 0);
    if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) == -1) return _ERR;
    return _OK;
}

int skcp_init_udp(const char* ip, unsigned short port, struct sockaddr_in* sock, int is_bind) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == fd) {
        perror("init_udp socket error");
        return _ERR;
    }
    int ret = skcp_net_set_nonblocking(fd);
    if (ret != _OK) {
        perror("init_udp set nonblocking error");
        close(fd);
        return _ERR;
    }
    /* struct sockaddr_in sockaddr; */
    memset(sock, 0, sizeof(struct sockaddr_in));
    sock->sin_family = AF_INET;
    sock->sin_addr.s_addr = inet_addr(ip);
    sock->sin_port = htons(port);
    if (is_bind) {
        ret = skcp_net_set_reuseaddr(fd);
        if (ret != _OK) {
            perror("init_udp set reuse addr error");
            close(fd);
            return _ERR;
        }
        ret = bind(fd, (struct sockaddr*)sock, sizeof(struct sockaddr));
        if (ret == -1) {
            perror("init_udp bind error");
            close(fd);
            return _ERR;
        }
    }
    return _OK;
}

int skcp_tcp_send(int fd, const char* buf, int len) {
    if (fd <= 0 || !buf || len <= 0) return -2;
    int rt, bytes;
    bytes = write(fd, buf, len);
    if (bytes == 0) {
        /* tcp close */
        rt = 0;
        _LOG("tcp_send close fd:%d len:%d", fd, len);
    } else if ((bytes == -1) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* EAGAIN */
        rt = -1;
        _LOG("tcp_send again fd:%d len:%d", fd, len);
    } else if ((bytes == -1) && !((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* error */
        /* TODO: debug */
        _LOG("tcp_send error fd:%d errno:%d %s", fd, errno, strerror(errno));
        rt = -2;
    } else {
        /* ok */
        rt = bytes;
        _LOG("tcp_send send ok. fd:%d len:%d", fd, rt);
    }

    return rt;
}

int skcp_tcp_read(int fd, char* buf, int len) {
    int ret;
    ret = read(fd, buf, len);
    if (ret == 0) {
        /* close */
        _LOG("tcp read close fd:%d", fd);
        return 0;
    } else if ((ret == -1) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* EAGAIN */
        _LOG("tcp read EAGAIN fd:%d errno:%d", fd, errno);
        return -1;
    } else if ((ret == -1) && !((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* error */
        _LOG("tcp read error, close fd:%d errno:%d", fd, errno);
        return -2;
    }
    _LOG("once read fd:%d ret:%d", fd, ret);
    return ret;
}