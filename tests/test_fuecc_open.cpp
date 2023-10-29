#include "crypto-protocol/fuecc_open.h"
#include <bits/stdc++.h>
using namespace std;
using namespace fucrypto;

void test_print_open_bn() {
  open_bn bn;
  //   open_bn bn1(bn);
  //   open_bn bn2 = bn;
  bigint* bn_ptr = &bn;
  bn_ptr->set_one();
  bn_ptr->print();
  bn_ptr->set_zero();
  bn_ptr->print();
  bn_ptr->set_long(255);
  bn_ptr->print();
  bn_ptr->set_long(-1);
  bn_ptr->print();
}
void test_check_open_bn() {
  open_bn bn;
  bigint* p = &bn;
  p->from_dec("15");
  p->print();
  p->from_dec("-255");
  p->print();
  p->set_long(-255);
  p->print();

  p->from_hex("FFFFFFFFFFFFFF01");
  p->print();
  unsigned char bin[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1};
  p->from_bin((char*)bin, 8);
  p->print();
}
int main(int argc, char** argv) {
  cout << "======= test ecc_open ========" << endl;
  //   test_print_open_bn();
  test_check_open_bn();
  return 0;
}