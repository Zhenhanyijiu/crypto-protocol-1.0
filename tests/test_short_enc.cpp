#include "crypto-protocol/short_enc.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/utils.h"
using namespace fucrypto;

struct argv_param {
  int max_msg_n = 256;
  int plain_num = 100;
  int plain_cipher_vector_num = 3;
};
argv_param get_argv_param(int argc, char** argv) {
  argv_param param;
  if (argc > 1) param.max_msg_n = atoi(argv[1]);
  if (argc > 2) param.plain_num = atoi(argv[2]);
  if (argc > 3) param.plain_cipher_vector_num = atoi(argv[3]);
  SPDLOG_LOGGER_INFO(
      spdlog::default_logger(),
      "最大消息 max_msg_n:{},明文个数:{},plain_cipher_vector_num:{}",
      param.max_msg_n, param.plain_num, param.plain_cipher_vector_num);
  return param;
}
int main_test(argv_param& param) {
  spdlog_set_level("info");
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== test short elgamal enc ======");
  int max_msg_n = param.max_msg_n;
  int plain_num = param.plain_num;
  //   auto c = (*ecc_lib_map)["openssl"]->new_curve("secp256k1");
  config_param defau;
  auto c = new_lib_curve(defau);
  if (!c) return 0;
  time_point tm_point;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher begin time:{} ms",
                     tm_point.get_time_piont_ms());
  short_elgamal::init_short_cipher(c.get(), max_msg_n);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher end time:{} ms",
                     tm_point.get_time_piont_ms());
  short_elgamal sh_elg;
  //   sh_elg.init_short_cipher(c.get(), msg_n);
  vector<uint32_t> plain(plain_num);
  for (size_t i = 0; i < plain_num; i++) {
    plain[i] = i % 2;
    // plain[i] = i % max_msg_n;
    // plain[i] = i;
  }

  auto pk = c->new_point();
  auto sk = c->gen_rand_bn();
  c->scalar_base_mul(sk.get(), pk.get());
  string cipher_0;
  std::vector<std::string> ciphers;
  //

  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== enc_list_fast begin time:{} ms",
                     tm_point.get_time_piont_ms());
  int fg = sh_elg.enc_list_fast(plain, cipher_0, ciphers, pk.get(), c.get());
  if (fg) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "enc_list_fast error");
    return 0;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== enc_list_fast end time:{} ms",
                     tm_point.get_time_piont_ms());
  for (size_t i = 0; i < 5 && i < ciphers.size(); i++) {
    // cout << "cipher_i:" << i << ",c0:" << cipher_0.size()
    //      << ",c1:" << ciphers[i].size() << endl;
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cipher_i:{},c0_size:{},c1_size:{}", i, cipher_0.size(),
                       ciphers[i].size());
  }

  //
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== dec_list_fast begin time:{} ms",
                     tm_point.get_time_piont_ms());
  vector<uint32_t> plain_dec;
  fg = sh_elg.dec_list_fast(cipher_0, ciphers, plain_dec, sk.get(), c.get());
  if (fg) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "dec_list error");
    return 0;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== dec_list_fast end time:{} ms",
                     tm_point.get_time_piont_ms());
  //   check
  if (plain.size() != plain_dec.size()) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "check error");
    return 0;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== check begin time:{} ms",
                     tm_point.get_time_piont_ms());
  for (int i = 0; i < plain.size(); i++) {
    if (plain[i] != plain_dec[i]) {
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "check val error i::{}", i);
      return 0;
    }
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== check end time:{} ms",
                     tm_point.get_time_piont_ms());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "check ok");
  return 0;
}

int main_test_enc_list_cipher_add(argv_param& param) {
  srand(time(NULL));
  spdlog_set_level("info");
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== test short elgamal enc ======");
  int max_msg_n = param.max_msg_n;
  int plain_num = param.plain_num;
  int plain_cipher_vector_num = param.plain_cipher_vector_num;
  //   auto c = (*ecc_lib_map)["openssl"]->new_curve("secp256k1");
  config_param defau;
  auto c = new_lib_curve(defau);
  if (!c) return 0;
  time_point tm_point;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher begin time:{} ms",
                     tm_point.get_time_piont_ms());
  short_elgamal::init_short_cipher(c.get(), max_msg_n);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher end time:{} ms",
                     tm_point.get_time_piont_ms());
  // pk, ks
  auto pk = c->new_point();
  auto sk = c->gen_rand_bn();
  c->scalar_base_mul(sk.get(), pk.get());
  //
  short_elgamal sh_elg;
  vector<vector<uint32_t>> plain_vector(plain_cipher_vector_num);
  vector<string> cipher0_vector(plain_cipher_vector_num);
  vector<vector<string>> cipher1_vector(plain_cipher_vector_num);
  for (size_t i = 0; i < plain_cipher_vector_num; i++) {
    plain_vector[i].resize(plain_num);
    for (size_t i2 = 0; i2 < plain_num; i2++) {
      plain_vector[i][i2] = rand() % 2;
    }

    cipher1_vector[i].resize(plain_num);
    sh_elg.enc_list_fast(plain_vector[i], cipher0_vector[i], cipher1_vector[i],
                         pk.get(), c.get());
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "====== enc_list_fast end");

  // 密文相加
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== enc_list_cipher_add start:{}ms",
                     tm_point.get_time_piont_ms());
  sh_elg.enc_list_cipher_add(cipher0_vector, cipher1_vector.data(), pk.get(),
                             c.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== enc_list_cipher_add end:{}ms",
                     tm_point.get_time_piont_ms());

  // 解密相加的结果
  vector<uint32_t> plain_dec;
  sh_elg.dec_list_fast(cipher0_vector[0], cipher1_vector[0], plain_dec,
                       sk.get(), c.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "====== dec_list_fast end");
  // check
  for (size_t i = 0; i < plain_num; i++) {
    int sum = 0;
    for (size_t i2 = 0; i2 < plain_cipher_vector_num; i2++) {
      sum += plain_vector[i2][i];
    }
    if (i < 10 && i < plain_num) {
      //   SPDLOG_LOGGER_INFO(spdlog::default_logger(),
      //                      "====== plain_vector add end");
      //   SPDLOG_LOGGER_INFO(spdlog::default_logger(), "======
      //   plain_dec.size:{}",
      //                      plain_dec.size());
      SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                         "====== sum:{},plain_dec[i]:{},i:{}", sum,
                         plain_dec[i], i);
    }
    // string tmp=cipher1_vector[0][i];

    if (sum != plain_dec[i]) {
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "====== check error i:{}",
                          i);
      return 0;
    }
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "====== check ok");
  return 0;
}
int main_test_enc_dec_batch(argv_param& param) {
  srand(time(NULL));
  spdlog_set_level("info");
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== main_test_enc_dec_batch ======");
  int max_msg_n = param.max_msg_n;
  int plain_num = param.plain_num;
  //   int plain_cipher_vector_num = param.plain_cipher_vector_num;
  //   auto c = (*ecc_lib_map)["openssl"]->new_curve("secp256k1");
  config_param defau;
  auto c = new_lib_curve(defau);
  if (!c) return 0;
  time_point tm_point;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher begin time:{} ms",
                     tm_point.get_time_piont_ms());
  short_elgamal::init_short_cipher(c.get(), max_msg_n);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher end time:{} ms",
                     tm_point.get_time_piont_ms());
  // pk, ks
  auto pk = c->new_point();
  auto sk = c->gen_rand_bn();
  c->scalar_base_mul(sk.get(), pk.get());
  //
  short_elgamal sh_elg;
  vector<uint32_t> plains(plain_num);
  std::vector<std::array<std::string, 2>> ciphers(plain_num);
  for (size_t i = 0; i < plain_num; i++) {
    // plains[i] = uint32_t(rand()) % max_msg_n;
    plains[i] = uint32_t(rand()) % 2;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== enc_batch begin time:{} ms",
                     tm_point.get_time_piont_ms());
  //   sh_elg.enc_batch(plains, ciphers, pk.get(), c.get());
  sh_elg.enc_batch_by_map(plains, ciphers, pk.get(), c.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== enc_batch end time:{} ms",
                     tm_point.get_time_piont_ms());
  // dec_batch
  vector<uint32_t> plains_dec(plain_num);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== dec_batch begin time:{} ms",
                     tm_point.get_time_piont_ms());
  //   sh_elg.dec_batch(ciphers, plains_dec, sk.get(), c.get());
  sh_elg.dec_batch_by_map(ciphers, plains_dec, sk.get(), c.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== dec_batch end time:{} ms",
                     tm_point.get_time_piont_ms());
  //  check
  for (size_t i = 0; i < plain_num; i++) {
    if (plains[i] != plains_dec[i]) {
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "=== check error");
      return 0;
    }
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== check ok");
  return 0;
}

int main_test_enc_dec_batch_pre_c0(argv_param& param) {
  srand(time(NULL));
  spdlog_set_level("info");
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== main_test_enc_dec_batch ======");
  int max_msg_n = param.max_msg_n;
  int plain_num = param.plain_num;
  //   int plain_cipher_vector_num = param.plain_cipher_vector_num;
  //   auto c = (*ecc_lib_map)["openssl"]->new_curve("secp256k1");
  config_param defau;
  auto c = new_lib_curve(defau);
  if (!c) return 0;
  time_point tm_point;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher begin time:{} ms",
                     tm_point.get_time_piont_ms());
  short_elgamal::init_short_cipher(c.get(), max_msg_n);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher end time:{} ms",
                     tm_point.get_time_piont_ms());
  // pk, ks
  auto pk = c->new_point();
  auto sk = c->gen_rand_bn();
  c->scalar_base_mul(sk.get(), pk.get());
  //
  short_elgamal sh_elg;
  vector<uint32_t> plains(plain_num);
  std::vector<std::array<std::string, 2>> ciphers(plain_num);
  for (size_t i = 0; i < plain_num; i++) {
    // plains[i] = uint32_t(rand()) % max_msg_n;
    plains[i] = uint32_t(rand()) % 2;
  }
  vector<string> t_list(plain_num);
  auto t = c->new_bn();
  auto tG = c->new_point();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== tG begin time:{} ms",
                     tm_point.get_time_piont_ms());
  for (size_t i = 0; i < plain_num; i++) {
    c->gen_rand_bn(t.get());
    c->scalar_base_mul(t.get(), tG.get());
    t_list[i] = t->to_bin();
    ciphers[i][0] = tG->to_bin();
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== tG end time:{} ms",
                     tm_point.get_time_piont_ms());

  auto G = c->get_generator();
  auto rt = c->gen_rand_bn();
  auto rtG = c->new_point();
  c->scalar_base_mul(rt.get(), rtG.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== ADD G begin time:{} ms",
                     tm_point.get_time_piont_ms());
  for (size_t i = 0; i < plain_num; i++) {
    c->add(G.get(), rtG.get());
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== ADD G end time:{} ms",
                     tm_point.get_time_piont_ms());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== enc_batch_pre_c0 begin time:{} ms",
                     tm_point.get_time_piont_ms());
  //   sh_elg.enc_batch(plains, ciphers, pk.get(), c.get());
  sh_elg.enc_batch_pre_c0(plains, t_list, ciphers, pk.get(), c.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== enc_batch_pre_c0 end time:{} ms",
                     tm_point.get_time_piont_ms());
  // dec_batch
  vector<uint32_t> plains_dec(plain_num);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== dec_batch begin time:{} ms",
                     tm_point.get_time_piont_ms());
  //   sh_elg.dec_batch(ciphers, plains_dec, sk.get(), c.get());
  sh_elg.dec_batch_by_map(ciphers, plains_dec, sk.get(), c.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== dec_batch end time:{} ms",
                     tm_point.get_time_piont_ms());
  //  check
  for (size_t i = 0; i < plain_num; i++) {
    if (plains[i] != plains_dec[i]) {
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "=== check error");
      return 0;
    }
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== check ok");
  return 0;
}

int main_test_batch_cipher_add_pre_c0(argv_param& param) {
  srand(time(NULL));
  spdlog_set_level("info");
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== test short elgamal enc ======");
  int max_msg_n = param.max_msg_n;
  int plain_num = param.plain_num;
  int plain_cipher_vector_num = param.plain_cipher_vector_num;
  //   auto c = (*ecc_lib_map)["openssl"]->new_curve("secp256k1");
  config_param defau;
  auto c = new_lib_curve(defau);
  if (!c) return 0;
  time_point tm_point;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher begin time:{} ms",
                     tm_point.get_time_piont_ms());
  short_elgamal::init_short_cipher(c.get(), max_msg_n);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== init_short_cipher end time:{} ms",
                     tm_point.get_time_piont_ms());
  // pk, ks
  auto pk = c->new_point();
  auto sk = c->gen_rand_bn();
  c->scalar_base_mul(sk.get(), pk.get());
  //
  short_elgamal sh_elg;
  vector<vector<uint32_t>> plain_vector(plain_cipher_vector_num);
  //   vector<string> cipher0_vector(plain_cipher_vector_num);
  vector<vector<array<string, 2>>> cipher_vector(plain_cipher_vector_num);
  for (size_t i = 0; i < plain_cipher_vector_num; i++) {
    plain_vector[i].resize(plain_num);
    for (size_t i2 = 0; i2 < plain_num; i2++) {
      plain_vector[i][i2] = rand() % 2;
    }
    cipher_vector[i].resize(plain_num);
    sh_elg.enc_batch(plain_vector[i], cipher_vector[i], pk.get(), c.get());
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "====== enc_list_fast end");

  // 密文相加
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== enc_list_cipher_add start:{}ms",
                     tm_point.get_time_piont_ms());
  sh_elg.batch_cipher_add(cipher_vector, pk.get(), c.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "====== enc_list_cipher_add end:{}ms",
                     tm_point.get_time_piont_ms());

  // 解密相加的结果
  vector<uint32_t> plain_dec;
  sh_elg.dec_batch_pre_c0(cipher_vector[0], plain_dec, sk.get(), c.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "====== dec_list_fast end");
  // check
  for (size_t i = 0; i < plain_num; i++) {
    int sum = 0;
    for (size_t i2 = 0; i2 < plain_cipher_vector_num; i2++) {
      sum += plain_vector[i2][i];
    }
    if (i < 10 && i < plain_num) {
      SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                         "====== sum:{},plain_dec[i]:{},i:{}", sum,
                         plain_dec[i], i);
    }
    if (sum != plain_dec[i]) {
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "====== check error i:{}",
                          i);
      return 0;
    }
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "====== check ok");
  return 0;
}

int main(int argc, char** argv) {
  argv_param param = get_argv_param(argc, argv);
  //   main_test(param);
  //   main_test_enc_list_cipher_add(param);
  //   main_test_enc_dec_batch(param);
  //   main_test_enc_dec_batch_pre_c0(param);
  main_test_batch_cipher_add_pre_c0(param);
  return 0;
}