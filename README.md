# SKCP
SKCP is a library of encapsulation of [KCP](https://github.com/skywind3000/kcp), it has the function of connection management and encryption.

## 状态
“又不是不能用”，应用在[SKCPTUN](https://github.com/xboss/skcptun)

## 特性
* 加密后的传输数据没有任何特征
* 具备基本的连接管理能力

## 环境
运行环境：Linux，MacOS

依赖库：[OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL.md#installing-openssl)，[libev](https://github.com/enki/libev)

## 使用
客户端代码中需要实现skcp_conf_t中的：
```
void (*on_recv_cid)(skcp_t *skcp, uint32_t cid);
void (*on_recv_data)(skcp_t *skcp, uint32_t cid, char *buf, int len);
void (*on_close)(skcp_t *skcp, uint32_t cid);
```

服务端代码中需要实现skcp_conf_t中的：
```
void (*on_accept)(skcp_t *skcp, uint32_t cid);
int (*on_check_ticket)(skcp_t *skcp, char *ticket, int len);
void (*on_recv_data)(skcp_t *skcp, uint32_t cid, char *buf, int len);
void (*on_close)(skcp_t *skcp, uint32_t cid);
```
编译测试代码：
```
cd skcp
mkdir build
make
```

运行测试服务端：
```
cd build
./skcp_server
```
目前测试服务端命令只能服务一个客户端，即点对点的服务，如果需要多个，需要起多个skcp_server进程，如同“netcat”。
默认监听127.0.0.1地址的6060端口。
可以通过参数指定监听的网络接口和端口以及加密的key：
```
./skcp_server 0.0.0.0 8080 yourpassword
```

运行测试客户端：
```
cd build
./skcp_client
```
默认连接127.0.0.1地址的6060端口。
可以通过参数指定需要连接的网络接口和端口以及加密的key：
```
./skcp_client 0.0.0.0 8080 yourpassword
```