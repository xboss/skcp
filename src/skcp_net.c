#include "skcp_net.h"

#include <fcntl.h>

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