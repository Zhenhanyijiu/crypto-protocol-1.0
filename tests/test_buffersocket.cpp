/********************* for test *****************************/
#include <bits/stdc++.h>
#include "crypto-protocol/buffersocket.h"
#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/fulog.h"

using namespace std;
using namespace fucrypto;
typedef shared_ptr<thread> task;
static task sender2(conn* c);
static task receiver2(conn* c);
static task sender(conn* c) {
  return make_shared<thread>(
      [](conn* c) {
        auto th = sender2(c);
        th->join();
        //////////////
        c->send("nihao_one");
        // cout << ">>>>>>>>>" << endl;
        string ret = c->recv();
        cout << "sender ret:" << ret << endl;
        c->close();
      },
      c);
}
static task receiver(conn* c) {
  return make_shared<thread>(
      [](conn* c) {
        auto th = receiver2(c);
        th->join();
        //////////////////
        string ret = c->recv();
        cout << "receiver ret:" << ret << endl;
        c->send(ret + "-11111111111111");
        c->close();
      },
      c);
}

static task sender2(conn* c) {
  return make_shared<thread>(
      [](conn* c) {
        c->send("nihao2---");
        string ret = c->recv();
        cout << "sender2 ret:" << ret << endl;
      },
      c);
}
static task receiver2(conn* c) {
  return make_shared<thread>(
      [](conn* c) {
        string ret = c->recv();
        cout << "receiver2 ret:" << ret << endl;
        c->send(ret + "22222222222222222");
      },
      c);
}

class R {
 private:
  buffersocket _sock;
  shared_ptr<thread> _th;
  shared_ptr<thread> _th_send;
  shared_ptr<thread> _th_recv;

 public:
  R(){};
  ~R() {
    _th->join();
    _th_send->join();
    _th_recv->join();
    cout << "~R 析构" << endl;
  };
  void run() { _th = receiver(&_sock); }
  void sendloop(connection& c) {
    _th_send = make_shared<thread>([&, this]() {
      for (;;) {
        string ret = _sock.get_msg();
        c.send(ret);
        if (ret == "eof") break;
      }
    });
  }

  void recvloop(connection& c) {
    _th_recv = make_shared<thread>([&, this]() {
      for (;;) {
        string ret = c.recv();
        if (ret == "eof") break;
        _sock.set_msg(ret);
      }
    });
  }
  //   string get_msg() { return _sock.get_msg(); };
  //   void set_msg(string data) { _sock.set_msg(data); };
};
class S {
 private:
  vector<buffersocket> sockss;
  buffersocket _sock;
  shared_ptr<thread> _th;
  shared_ptr<thread> _th_send;
  shared_ptr<thread> _th_recv;

 public:
  S() {
    // sockss.push_back(buffersocket());
    buffersocket b1;
    buffersocket b2 = b1;
  };
  ~S() {
    _th->join();
    _th_send->join();
    _th_recv->join();
    cout << "~S 析构" << endl;
  };
  void run() { _th = sender(&_sock); };
  //   string get_msg() { return _sock.get_msg(); };
  //   void set_msg(string data) { _sock.set_msg(data); };
  void sendloop(connection& c) {
    _th_send = make_shared<thread>([&, this]() {
      for (;;) {
        string ret = _sock.get_msg();
        c.send(ret);
        if (ret == "eof") break;
      }
    });
  }

  void recvloop(connection& c) {
    _th_recv = make_shared<thread>([&, this]() {
      for (;;) {
        string ret = c.recv();
        if (ret == "eof") break;
        _sock.set_msg(ret);
      }
    });
  }
};

static int main_test(int argc, char** argv) {
  //   cout << "test here ..." << CLIENT << endl;
  int role = 0;
  if (argc == 1) {
    cout << "param wrong" << endl;
    return 0;
  }
  if (argc > 1) role = atoi(argv[1]);
  string s = role == 0 ? "here is client" : "here is server";
  //   cout << "role :" << s << endl;
  buffersocket c_sender, c_receiver;
  auto th1 = sender(&c_sender);
  auto th2 = receiver(&c_receiver);
  auto th3 = sender2(&c_sender);
  auto th4 = receiver2(&c_receiver);
  //
  //   string m3 = c_sender.get_msg();
  //   c_receiver.set_msg(m3);
  //   string m4 = c_receiver.get_msg();
  //   c_sender.set_msg(m4);
  thread th([&]() {
    string m = c_sender.get_msg();
    c_receiver.set_msg(m);
    string m2 = c_receiver.get_msg();
    c_sender.set_msg(m2);

    string m3 = c_sender.get_msg();
    c_receiver.set_msg(m3);
    string m4 = c_receiver.get_msg();
    c_sender.set_msg(m4);
  });

  th1->join();
  th2->join();

  cout << "========== th1 th2 end" << endl;
  int aa;

  th3->join();
  th4->join();

  th.join();
  return 0;
}
static void main_buffer_test(int argc, char** argv) {
  int role = 0;
  if (argc == 1) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "param wrong");
    return;
  }
  if (argc > 1) role = atoi(argv[1]);
  string s = role == 0 ? "here is client" : "here is server";
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "role is:{}", s);

  vector<buffersocket> sock;
  if (role == 0) {
    connection c(0, "127.0.0.1", 18888);
    S s;
    s.run();
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "S");

    // c.send(s.get_msg());
    // s.set_msg(c.recv());
    // thread th([&]() {
    // c.send(s.get_msg());
    // s.set_msg(c.recv());
    // });
    // th.join();

    s.sendloop(c);
    s.recvloop(c);

  } else {
    connection c(1, "127.0.0.1", 18888);
    R r;
    r.run();
    // cout << "=======>>" << endl;
    // thread th([&]() {
    // r.set_msg(c.recv());
    // c.send(r.get_msg());
    // });
    // th.join();
    r.sendloop(c);
    r.recvloop(c);
  }
}

int main(int argc, char** argv) {
  spdlog_set_level("info");
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "test ......");
  int count = 1;
  //   count = 1;
  for (size_t i = 0; i < count; i++) {
    // main_test(argc, argv);
    main_buffer_test(argc, argv);
  }
  return 0;
}
