# SKCP
SKCP is encapsulation of [KCP](https://github.com/skywind3000/kcp), it has the function of connection management and encryption.

## 状态
“又不是不能用”，在[SKCPTUN](https://github.com/xboss/skcptun)中被使用。

## 特性
* 加密后的传输数据没有任何特征
* 具备基本的连接管理能力

## 环境
运行环境：Linux，MacOS

依赖库：[OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL.md#installing-openssl)，[libev](http://pod.tst.eu/http://cvs.schmorp.de/libev/ev.pod)

## 使用
客户端代码中需要实现skcp_conf_t中的：
```
void (*on_recv_cid)(uint32_t cid);
void (*on_recv_data)(uint32_t cid, char *buf, int len);
void (*on_close)(uint32_t cid);
```

服务端代码中需要实现skcp_conf_t中的：
```
void (*on_accept)(uint32_t cid);
int (*on_check_ticket)(char *ticket, int len);
void (*on_recv_data)(uint32_t cid, char *buf, int len);
void (*on_close)(uint32_t cid);
```
编译测试代码：
```
cd skcp
mkdir build
make
```