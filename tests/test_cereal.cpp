#include <cereal/types/unordered_map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/array.hpp>
#include <cereal/archives/binary.hpp>
#include <bits/stdc++.h>
#include <fstream>
using namespace std;
struct MyRecord {
  uint8_t x, y;
  float z;

  template <class Archive>
  void serialize(Archive& ar) {
    ar(x, y, z);
  }
};

struct SomeData {
  int32_t id;
  std::shared_ptr<std::unordered_map<uint32_t, MyRecord>> data;

  template <class Archive>
  void save(Archive& ar) const {
    ar(id, data);
  }

  template <class Archive>
  void load(Archive& ar) {
    // static int32_t idGen = 0;
    // id = idGen++;
    ar(id, data);
  }
};

void print(string s) {
  for (size_t i = 0; i < s.size(); i++) {
    printf("%2x,", (unsigned char)s[i]);
  }
  cout << endl;
}

int main2() {
  MyRecord mr;
  mr.x = 123;
  mr.y = 1231;
  mr.z = 1235;
  stringstream os;
  cereal::BinaryOutputArchive archive(os);
  //   cereal::serialize(,);
  return 0;
  ;
}
int main1() {
  //   std::ofstream os("out.cereal", std::ios::binary);
  stringstream os;
  cereal::BinaryOutputArchive archive(os);

  SomeData myData;
  myData.id = 100007;
  archive(myData);
  string s = os.str();
  cout << "os.size:" << s.size() << endl;
  print(s);
  stringstream os2;
  os2 << s;
  cereal::BinaryInputArchive load(os2);
  //   cereal::serialize
  SomeData sd2;
  load(sd2);
  cout << "id:" << sd2.id << endl;
  return 0;
}

int main3() {
  //   std::ofstream os("out.cereal", std::ios::binary);
  stringstream os;
  cereal::BinaryOutputArchive archive(os);

  SomeData myData;
  myData.id = 100007555;
  archive(myData);
  //   myData.save(archive);
  string s = os.str();
  cout << "os.size:" << s.size() << endl;
  print(s);
  stringstream os2;
  os2 << s;
  cereal::BinaryInputArchive load(os2);
  //   cereal::serialize
  SomeData sd2;
  load(sd2);
  cout << "id:" << sd2.id << endl;
  return 0;
}

struct message {
  int id;
  string A;
  string C;
  template <class Archive>
  void save(Archive& ar) const {
    ar(A, C, id);
  }

  template <class Archive>
  void load(Archive& ar) {
    ar(A, C, id);
  }
};

int main1023() {
  cout << "messages sizeof:" << sizeof(message) << endl;
  message msg1 = {20007, "222222222", "5555555555555555"};
  stringstream ss1;
  cereal::BinaryOutputArchive arch(ss1);
  arch(msg1);
  string ret = ss1.str();
  cout << "msg1:" << ret << " ,size:" << ret.size() << endl;
  print(ret);
  stringstream ss2(ret);
  cereal::BinaryInputArchive arch2(ss2);
  message msg2;
  arch2(msg2);
  cout << "A:" << msg2.A << ",C" << msg2.C << ",id:" << msg2.id << endl;
  return 0;
}
// int main() {
//   vector<int> ret = {12, 13, 17};

//   stringstream ss1;
//   cereal::BinaryOutputArchive arch(ss1);
//   arch(ret);
//   print(ss1.str());
//   return 0;
// }

// struct np99msg_PKs {
//   vector<string> pks;
//   template <class Archive>
//   void save(Archive& ar) const {
//     ar(pks);
//   }
//   template <class Archive>
//   void load(Archive& ar) {
//     ar(pks);
//   }
// };

int main1051() {
  //   np99msg_PKs msg;
  auto pks = vector<string>{"AA", "BB", "CC"};
  //   msg.pks = pks;
  cout << "len:" << pks.size() << endl;
  stringstream ss;
  cereal::BinaryOutputArchive out1(ss);
  out1(pks);
  cout << "out:" << ss.str() << endl;

  vector<string> in_vec;
  cout << "input === in_vec.size:" << in_vec.size() << endl;

  cereal::BinaryInputArchive in1(ss);
  in1(in_vec);
  for (size_t i = 0; i < in_vec.size(); i++) {
    cout << "i:" << i << ", " << in_vec[i] << endl;
  }

  return 0;
}

int main() {
  //   np99msg_PKs msg;
  auto pks = array<string, 3>{"AA", "BB", "CC"};
  //   msg.pks = pks;
  cout << "len:" << pks.size() << endl;
  stringstream ss;
  cereal::BinaryOutputArchive out1(ss);
  out1(pks);
  cout << "out:" << ss.str() << endl;

  array<string, 3> in_vec;
  cout << "array<string, 3> input === in_vec.size:" << in_vec.size() << endl;

  cereal::BinaryInputArchive in1(ss);
  in1(in_vec);
  for (size_t i = 0; i < in_vec.size(); i++) {
    cout << "i:" << i << ", " << in_vec[i] << endl;
  }

  return 0;
}