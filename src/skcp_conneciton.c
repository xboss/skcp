#include "skcp_connection.h"

/* -------------------------------------------------------------------------- */
/*                              connection slots                              */
/* -------------------------------------------------------------------------- */

skcp_conn_slots_t *skcp_init_conn_slots(uint32_t max_conns) {
    skcp_conn_slots_t *slots = (skcp_conn_slots_t *)SKCP_ALLOC(sizeof(skcp_conn_slots_t));
    slots->max_cnt = max_conns > 0 ? max_conns : SKCP_MAX_CONNS;
    slots->remain_cnt = slots->max_cnt;
    // slots->conns = (skcp_conn_t **)SKCP_ALLOC(slots->max_cnt * sizeof(skcp_conn_t));
    slots->conns = (skcp_conn_t **)SKCP_ALLOC(slots->max_cnt * sizeof(skcp_conn_t *));
    slots->remain_id_stack = (uint32_t *)SKCP_ALLOC(slots->max_cnt * sizeof(uint32_t));
    for (uint32_t i = 0; i < slots->max_cnt; i++) {
        slots->remain_id_stack[i] = i + 1;
    }
    slots->remain_idx = 0;
    return slots;
}

void skcp_free_conn_slots(skcp_conn_slots_t *slots) {
    if (!slots) {
        return;
    }
    SKCP_FREEIF(slots->conns);
    SKCP_FREEIF(slots->remain_id_stack);
    SKCP_FREEIF(slots);
}

skcp_conn_t *skcp_get_conn_from_slots(skcp_conn_slots_t *slots, uint32_t cid) {
    if (slots == NULL || cid <= 0 || cid > slots->max_cnt) {
        return NULL;
    }
    return slots->conns[cid - 1];
}

// 借一个连接id，仅供slots内部使用，失败返回0，成功返回cid
uint32_t skcp_borrow_cid_from_slots(skcp_conn_slots_t *slots) {
    if (!slots || !slots->remain_id_stack || slots->remain_cnt <= 0 || slots->remain_cnt > slots->max_cnt ||
        slots->remain_idx > (slots->max_cnt - 1) || slots->remain_idx < 0) {
        return 0;
    }
    uint32_t cid = slots->remain_id_stack[slots->remain_idx];
    slots->remain_idx++;
    slots->remain_cnt--;
    return cid;
}

// 归还一个连接id，仅供slots内部使用，失败返回-1，成功返回0
int skcp_return_cid_to_slots(skcp_conn_slots_t *slots, uint32_t cid) {
    if (!slots || !slots->remain_id_stack || slots->remain_cnt < 0 || slots->remain_cnt >= slots->max_cnt ||
        slots->remain_idx > slots->max_cnt || slots->remain_idx <= 0 || cid <= 0) {
        return -1;
    }
    slots->remain_idx--;
    slots->remain_id_stack[slots->remain_idx] = cid;
    slots->remain_cnt++;
    return 0;
}

// 添加一个新连接到slots，注意此时传进来的conn中的cid并没有生成，失败返回0，成功返回cid
uint32_t skcp_add_new_conn_to_slots(skcp_conn_slots_t *slots, skcp_conn_t *conn) {
    if (!slots || !conn) {
        return 0;
    }
    conn->id = skcp_borrow_cid_from_slots(slots);
    if (conn->id <= 0) {
        return 0;
    }

    uint32_t i = conn->id - 1;
    if (slots->conns[i] != NULL) {
        skcp_return_cid_to_slots(slots, conn->id);
        return 0;
    }
    slots->conns[i] = conn;
    return conn->id;
}

// 覆盖一个连接到slots，失败返回0，成功返回cid
uint32_t skcp_replace_conn_to_slots(skcp_conn_slots_t *slots, skcp_conn_t *conn) {
    if (!slots || !conn || conn->id <= 0) {
        return 0;
    }

    slots->conns[conn->id - 1] = conn;
    return conn->id;
}

// 从slots中删除一个连接，并且归还cid，失败返回-1，成功返回0
int skcp_del_conn_from_slots(skcp_conn_slots_t *slots, uint32_t cid) {
    if (!slots || cid <= 0) {
        return -1;
    }
    // int rt = skcp_return_cid_to_slots(slots, cid);
    // if (rt != 0) {
    //     return -1;
    // }
    skcp_return_cid_to_slots(slots, cid);
    slots->conns[cid - 1] = NULL;

    return 0;
}

/* -------------------------------------------------------------------------- */
/*                               connection api                               */
/* -------------------------------------------------------------------------- */

skcp_conn_t *skcp_init_conn(skcp_conn_slots_t *conn_slots, skcp_conf_t *conf, uint32_t cid, skcp_io_t **io_list,
                            uint io_cnt) {
    if (!conn_slots || !conf || !io_list || io_cnt <= 0) {
        return 0;
    }

    skcp_conn_t *conn = (skcp_conn_t *)SKCP_ALLOC(sizeof(skcp_conn_t));
    conn->last_r_tm = conn->last_w_tm = skcp_getmillisecond();
    conn->status = SKCP_CONN_ST_ON;  // SKCP_CONN_ST_READY;
    conn->conn_slots = conn_slots;
    conn->conf = conf;

    if (cid <= 0) {
        cid = skcp_add_new_conn_to_slots(conn->conn_slots, conn);
        if (cid == 0) {
            skcp_free_conn(conn_slots, conn->id);
            return NULL;
        }
    } else {
        conn->id = cid;
        if (skcp_replace_conn_to_slots(conn->conn_slots, conn) == 0) {
            skcp_free_conn(conn_slots, conn->id);
            return NULL;
        }
    }

    ikcpcb *kcp = ikcp_create(cid, conn);
    ikcp_wndsize(kcp, conf->sndwnd, conf->rcvwnd);
    ikcp_nodelay(kcp, conf->nodelay, conf->interval, conf->nodelay, conf->nc);
    ikcp_setmtu(kcp, conf->mtu);
    // kcp->rx_minrto = 10;  // TODO: for test
    conn->kcp = kcp;

    uint idx = skcp_route_io(cid, io_cnt);
    conn->io = io_list[idx];
    if (conn->io->mode == SKCP_IO_MODE_CLIENT) {
        conn->dst_addr = conn->io->serv_addr;
    }

    conn->tick_watcher = malloc(sizeof(ev_timer));

    return conn;
}

skcp_conn_t *skcp_get_conn(skcp_conn_slots_t *conn_slots, uint32_t cid) {
    return skcp_get_conn_from_slots(conn_slots, cid);
}

void skcp_free_conn(skcp_conn_slots_t *conn_slots, uint32_t cid) {
    if (!conn_slots || cid <= 0) {
        return;
    }

    skcp_conn_t *conn = skcp_get_conn_from_slots(conn_slots, cid);
    if (!conn) {
        return;
    }
    skcp_del_conn_from_slots(conn_slots, cid);
    conn->status = SKCP_CONN_ST_OFF;
    conn->id = 0;
    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }
    conn->io = NULL;
    // TODO: break tick_watcher
}
