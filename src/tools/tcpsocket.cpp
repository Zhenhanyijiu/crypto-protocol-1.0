#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/futime.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
// #include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include "assert.h"
#include <netinet/tcp.h>
#include <new>
#include <bits/stdc++.h>
namespace fucrypto {
using namespace std;
typedef struct Channel Channel;
void *init_channel(RoleType pltype, const char *address, int port);
int send_data(void *channel, const char *buff, int buf_size);
int recv_data(void *channel, char **buff_output);
int release_channel(void *ch);
// 30M
#define RECV_BUFF_SIZE 1024 * 1024 * 30
// #define RECV_BUFF_SIZE 256

bool is_time_out(uint64_t start_time, long timeout_sec) {
  std::chrono::steady_clock::time_point n0;
  std::chrono::steady_clock::time_point n1 = std::chrono::steady_clock::now();
  auto dur = std::chrono::duration_cast<std::chrono::nanoseconds>(n1 - n0);
  uint64_t use_ns = dur.count() - start_time;
  if (use_ns > timeout_sec * 1000000000) return true;
  return false;
}
struct Channel {
  // int _socket_fd;
  int _conn;
  //   char *_recv_buff;
  vector<char> _recv_buff;
  uint32_t _recv_buff_len;
};
void set_nodelay() {
  // const int one = 1;
  // setsockopt(consocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}
void *init_channel(RoleType pltype, const char *address, int port) {
  Channel *ch = new (std::nothrow) Channel;
  if (ch == nullptr) return nullptr;

  if (pltype == CLIENT) {
    int socket_fd = 0;  // socket句柄
    // unsigned int iRemoteAddr = 0;
    struct sockaddr_in stRemoteAddr = {0};  // 对端，即目标地址信息
    memset(&stRemoteAddr, 0, sizeof(stRemoteAddr));

    stRemoteAddr.sin_family = AF_INET;
    stRemoteAddr.sin_port = htons(port);
    // inet_pton(AF_INET, ADDR, &iRemoteAddr);
    // stRemoteAddr.sin_addr.s_addr = iRemoteAddr;
    stRemoteAddr.sin_addr.s_addr = inet_addr(address);

    // 连接方法： 传入句柄，目标地址，和大小
    // long starttime = start_time_channel();
    uint64_t starttime = get_time_now<uint64_t>();
    printf("[tcpsocket.cpp] starttime:%ld\n", starttime);
    long timeout_sec = 3600;
    while (1) {
      socket_fd = socket(AF_INET, SOCK_STREAM, 0);  // 建立socket
      if (0 > socket_fd) {
        printf("[tcpsocket.cpp] client 创建 socket 失败！\n");
        continue;
      }
      int fg = connect(socket_fd, (struct sockaddr *)&stRemoteAddr,
                       sizeof(struct sockaddr));
      if (fg < 0) {
        if (is_time_out(starttime, timeout_sec)) {
          printf("[tcpsocket.cpp]client 连接失败 error dial timeout!\n");
          close(socket_fd);
          return nullptr;
        }
        close(socket_fd);
        continue;
      } else {
        printf("[tcpsocket.cpp] client 连接成功！\n");
        break;
      }
    }

    // recv(iSocketFD, buf, sizeof(buf), 0);
    // 将接收数据打入buf，参数分别是句柄，储存处，最大长度，其他信息（设为0即可）。 
    // Channel *ch = (Channel *)malloc(sizeof(Channel));
    // if (ch == nullptr)
    // {
    //     close(socket_fd);
    //     return nullptr;
    // }
    // ch->recv_buff = (char *)malloc(RECV_BUFF_SIZE); //100M
    // ch->_recv_buff = new char[RECV_BUFF_SIZE];  // 100M
    ch->_recv_buff.resize(RECV_BUFF_SIZE);
    // if (ch->recv_buff == nullptr)
    // {
    //     free(ch);
    //     close(socket_fd);
    //     return nullptr;
    // }
    ch->_recv_buff_len = RECV_BUFF_SIZE;
    // ch->_socket_fd = -1;
    ch->_conn = -1;
    ch->_conn = socket_fd;
    memset(ch->_recv_buff.data(), 0, ch->_recv_buff_len);
    return ch;
  }
  if (pltype == SERVER) {
    // 调用socket函数返回的文件描述符
    int socket_fd;
    // 声明两个套接字sockaddr_in结构体变量，分别表示客户端和服务器
    struct sockaddr_in server_addr = {0};
    struct sockaddr_in clientAddr = {0};
    socklen_t addr_len = sizeof(clientAddr);
    int conn;

    // 初始化服务器端的套接字，并用 htons 和 htonl 将端口和地址转成网络字节序
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

#ifdef IP_ENABLE
    unsigned int localAddr = 0;
    inet_pton(AF_INET, INADDR_ANY, &localAddr);
    // server_addr.sin_addr.s_addr =localAddr;
    // inet_addr("127.0.0.1");
    server_addr.sin_addr.s_addr = inet_addr(address);
#else
    // ip可是是本服务器的ip，也可以用宏 INADDR_ANY
    // 代替，代表0.0.0.0，表明所有地址
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    printf("[tcpsocket.cpp] listen all ip.\n");
#endif
    // socket函数，失败返回-1
    // int socket(int domain, int type, int protocol);
    // 第一个参数表示使用的地址类型，一般都是ipv4，AF_INET
    // 第二个参数表示套接字类型：tcp：面向连接的稳定数据传输SOCK_STREAM
    // 第三个参数设置为0
    // socket(AF_INET, SOCK_STREAM, 0);
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      printf("[tcpsocket.cpp] socket error\n");
      return nullptr;
    }
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
               sizeof(reuse));
    // 对于bind，accept之类的函数，里面套接字参数都是需要强制转换成(struct
    // sockaddr *)
    //  bind三个参数：服务器端的套接字的文件描述符，
    if (bind(socket_fd, (struct sockaddr *)&server_addr,
             sizeof(struct sockaddr)) < 0) {
      printf("[tcpsocket.cpp] connect bind error\n");
      close(socket_fd);
      return nullptr;
    }
    // 设置服务器上的socket为监听状态
    if (listen(socket_fd, 1) < 0) {
      printf("[tcpsocket.cpp] listen error\n");
      close(socket_fd);
      return nullptr;
    }
    conn = accept(socket_fd, (struct sockaddr *)&clientAddr,
                  (socklen_t *)&addr_len);
    if (conn < 0) {
      printf("[tcpsocket.cpp] accept error\n");
      close(socket_fd);
      return nullptr;
    }
    close(socket_fd);

    // Channel *ch = (Channel *)malloc(sizeof(Channel));
    // if (ch == nullptr)
    // {
    //     close(conn);
    //     close(socket_fd);
    //     return nullptr;
    // }
    // ch->recv_buff = (char *)malloc(RECV_BUFF_SIZE); //100M
    // ch->_recv_buff = new char[RECV_BUFF_SIZE];  // 100M
    ch->_recv_buff.resize(RECV_BUFF_SIZE);  // 100M
    // if (ch->recv_buff == nullptr)
    // {
    //     free(ch);
    //     close(conn);
    //     close(socket_fd);
    //     return nullptr;
    // }
    ch->_recv_buff_len = RECV_BUFF_SIZE;
    // ch->_socket_fd = -1;
    ch->_conn = -1;
    printf("[tcpsocket.cpp] accept ok...\n");
    // ch->_socket_fd = socket_fd;
    ch->_conn = conn;
    memset(ch->_recv_buff.data(), 0, ch->_recv_buff_len);
    return ch;
  }
  const int one = 1;
  setsockopt(ch->_conn, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  return nullptr;
}
int release_channel(void *ch) {
  if (ch) {
    Channel *c = (Channel *)ch;
    if (c->_conn >= 0) close(c->_conn);
    // if (c->_socket_fd >= 0)
    // {
    //     close(c->_socket_fd);
    // }
    // free(c->recv_buff);
    // delete[] c->_recv_buff;
    // c->_recv_buff = nullptr;
    // free(ch);
    delete c;
    c = nullptr;
    printf("[tcpsocket.cpp] release channel.\n");
  }
  return 0;
}

int send_data(void *channel, const char *buff, int buf_size) {
  if (channel == nullptr || buf_size < 0) {
    return -120;
  }
  if (buf_size == 0) {
    return 0;
  }
  uint32_t headlen = (uint32_t)buf_size;
  Channel *chan = (Channel *)channel;
  // char head[4] = {0};
  // memcpy(head, (char *)&headlen, 4);
  ssize_t n = send(chan->_conn, (char *)&headlen, 4, 0);
  assert(n == 4);
  if (n != 4) {
    printf("[tcpsocket.cpp] send header error,n(%ld)\n", n);
    return -121;
  }
  int offset = 0;
  int remain_len = buf_size;
  while (1) {
    n = send(chan->_conn, buff + offset, remain_len, 0);
    if (n < 0) {
      return -111;
    }
    offset += n;
    if (offset < buf_size) {
      remain_len = buf_size - offset;
      continue;
    } else {
      break;
    }
  }
  // n = send(chan->conn, buff, buf_size, 0);
  // assert(n == buf_size);
  return buf_size;
}
int recv_data(void *channel, char **buff_output) {
  if (channel == nullptr) {
    printf("[tcpsocket.cpp] error...1\n");
    return -122;
  }
  Channel *chan = (Channel *)channel;
  uint32_t headlen = 0;
  int n = 0;

  // 读四个字节头
  uint32_t offset = 0;
  int remain_len = 4;
  while (1) {
    n = recv(chan->_conn, (char *)(&headlen) + offset, remain_len, 0);
    if (n < 0) {
      printf("[tcpsocket.cpp] recv error in head,n:%d\n", n);
      return -111;
    }
    if (n == 0) {
      printf("[tcpsocket.cpp] connection closed!,n:%d\n", n);
      return 0;
    }
    offset += n;
    if (offset < 4) {
      remain_len = 4 - offset;
      continue;
    } else {
      break;
    }
  }

  // 空间不够
  if (headlen > chan->_recv_buff_len) {
    // char *tmp_buf = (char *)realloc(chan->recv_buff, headlen);
    // delete[] chan->_recv_buff;
    // chan->_recv_buff = new char[headlen];
    chan->_recv_buff.resize(headlen);
    // if (tmp_buf == nullptr)
    // {
    //     return -112;
    // }
    // chan->recv_buff = tmp_buf;
    chan->_recv_buff_len = headlen;
    memset(chan->_recv_buff.data(), 0, headlen);
  }
  // 这里要循环接收数据
  offset = 0;
  remain_len = headlen;
  // int count = 0;
  while (1) {
    n = recv(chan->_conn, chan->_recv_buff.data() + offset, remain_len, 0);
    if (n < 0) {
      printf("[tcpsocket.cpp] error...4,n(%d),headlen(%d)\n", n, headlen);
      return -111;
    }
    if (n == 0) {
      printf("[tcpsocket.cpp] connection closed!,n:%d\n", n);
      return 0;
    }
    // count++;
    offset += n;
    if (offset < headlen) {
      remain_len = headlen - offset;
      continue;
    } else {
      break;
    }
  }
  *buff_output = chan->_recv_buff.data();
  return headlen;
}

class init_error : public exception {
 private:
 public:
  init_error(){};
  ~init_error(){};
  const char *what() const throw() { return "init channel error"; }
};

connection::connection(int role, const std::string ip_addr, int port) {
  if (role == CLIENT)
    _conn = init_channel(CLIENT, ip_addr.c_str(), port);
  else
    _conn = init_channel(SERVER, ip_addr.c_str(), port);
  if (!_conn) {
    throw init_error();
  }
}
connection::~connection() {
  if (_conn) {
    release_channel(_conn);
  }
  cout << "~connection tcp" << endl;
}
int connection::send(const std::string data) {
  return send_data(_conn, data.c_str(), data.size());
}
std::string connection::recv() {
  char *buf = nullptr;
  int n = recv_data(_conn, &buf);
  if (n > 0) {
    return string(buf, n);
  }
  return string();
}
int connection::close() { return 0; }
// test
void main_test_channel(int argc, char **argv) {
  assert(argc > 1);
  int r = atoi(argv[1]);
  const char *addr = "127.0.0.1";
  int port = 8888;
  if (argc > 2) {
    port = atoi(argv[2]);
  }
  if (r == 0) {
    void *client = init_channel(CLIENT, addr, port);
    if (client == nullptr) return;
    send_data(client, "aa", 2);
    char *buf = nullptr;
    int n = recv_data(client, &buf);
    char res[128] = {0};
    memcpy(res, buf, n);
    printf("[tcpsocket.cpp] client:%s\n", res);
    release_channel(client);
  }
  if (r == 1) {
    void *server = init_channel(SERVER, addr, port);
    if (server == nullptr) return;

    char *buf = nullptr;
    int n = recv_data(server, &buf);
    char res[10] = {0};
    memcpy(res, buf, n);
    printf("[tcpsocket.cpp] server:%s\n", res);
    send_data(server, "aabb", 4);
    release_channel(server);
  }
}
}  // namespace fucrypto
