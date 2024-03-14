#include "crypto-protocol/cuckoo_simple_hash.h"
#include <bits/stdc++.h>
using namespace std;
int ele_num = 10;
int hash_num = 3;
float factor = 1.27;

static uint64_t get_rn() {
  uint64_t n1 = rand();
  uint64_t n2 = rand();
  uint64_t n3 = rand();
  return (n1 << 33) | (n2 << 2) | (n3 & 0x11);
}

static void print_cc_table(ENCRYPTO::CuckooTable& cc) {
  cout << "============== cc hash log ===============" << endl;
  auto vec_num = cc.GetNumOfElementsInBins();
  for (size_t i = 0; i < vec_num.size(); i++) {
    cout << "i:" << setw(2) << i << "," << vec_num[i] << endl;
  }
  // cc.MapElements()
  cout << "StashSize:" << cc.GetStashSize() << endl;
  auto value = cc.ObtainEntryValues();
  for (size_t i = 0; i < value.size(); i++) {
    cout << "i:" << setw(2) << i << "," << value[i] << endl;
  }
}

static void print_sp_table(ENCRYPTO::SimpleTable& sp) {
  cout << "\n============== sp hash log ===============" << endl;
  auto vec_num = sp.GetNumOfElementsInBins();
  for (size_t i = 0; i < vec_num.size(); i++) {
    cout << "i:" << setw(2) << i << "," << vec_num[i] << endl;
  }
  auto value = sp.ObtainBinEntryValues();
  for (size_t i = 0; i < value.size(); i++) {
    cout << "i:" << setw(2) << i << "#";
    for (size_t i2 = 0; i2 < value[i].size(); i2++) {
      cout << value[i][i2] << ",";
    }
    cout << endl;
  }
}
static int test_cc(int argc, char** argv) {
  srand((unsigned int)time(NULL));
  std::vector<std::uint64_t> elements;
  uint64_t mask = 0xffffffff;
  for (size_t i = 0; i < ele_num; i++) {
    // elements.push_back(mask & get_rn());
    elements.push_back(1 + i);
  }

  // cc_hash
  ENCRYPTO::CuckooTable cc(factor);
  cc.SetNumOfHashFunctions(hash_num);
  cc.Insert(elements);
  cc.MapElements();
  print_cc_table(cc);
  return 0;
}

static int test_sp(int argc, char** argv) {
  srand((unsigned int)time(NULL));
  std::vector<std::uint64_t> elements;
  uint64_t mask = 0xffffffff;
  for (size_t i = 0; i < ele_num; i++) {
    // elements.push_back(mask & get_rn());
    elements.push_back(i + 1);
  }
  //   sm_hash
  ENCRYPTO::SimpleTable sp(factor);
  sp.SetNumOfHashFunctions(hash_num);
  sp.Insert(elements);
  sp.MapElements();
  print_sp_table(sp);
  return 0;
}
void test_get_rn() {
  for (size_t i = 0; i < 100; i++) {
    cout << get_rn() << endl;
  }
}
int main(int argc, char** argv) {
  test_cc(argc, argv);
  test_sp(argc, argv);
  test_get_rn();
  return 0;
}