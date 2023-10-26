#include "crypto-protocol/tcpsocket.h"
#include <bits/stdc++.h>
using namespace std;
using namespace fucrypto;

void main_test_conn(int argc, char **argv) {
  assert(argc > 1);
  int r = atoi(argv[1]);
  const char *addr = "127.0.0.1";
  int port = 8888;
  if (argc > 2) {
    port = atoi(argv[2]);
  }
  try {
    if (r == 0) {
      conn *client = new connection(0, addr, port);
      if (client == nullptr) return;

      client->send("aa");
      string ret = client->recv();
      printf("[tcpsocket.cpp] client:%s\n", ret.c_str());
      ret = client->recv();
      printf("[tcpsocket.cpp] client:%s\n", ret.c_str());
      delete client;
    }
    if (r == 1) {
      conn *server = new connection(1, addr, port);
      if (server == nullptr) return;

      string ret = server->recv();
      printf("[tcpsocket.cpp] server:%s\n", ret.c_str());
      server->send("aabb");
      server->send("aabb555");
      delete server;
    }

  } catch (const std::exception &e) {
    std::cerr << "init conn error:" << e.what() << '\n';
    return;
  }

  //   sleep(1);
}

int main(int argc, char **argv) {
  main_test_channel(argc, argv);
  main_test_conn(argc, argv);
  return 0;
}
