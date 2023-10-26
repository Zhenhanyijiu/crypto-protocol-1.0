#ifndef __FU_TIME_H__
#define __FU_TIME_H__
#include <chrono>
// namespace utils {
// using namespace chrono;
using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;
template <typename T>
T get_time_now() {
  //   std::cout << "===========1\n";
  std::chrono::steady_clock::time_point n0;
  std::chrono::steady_clock::time_point n1 = std::chrono::steady_clock::now();
  auto dur = std::chrono::duration_cast<std::chrono::nanoseconds>(n1 - n0);
  return T(dur.count());
};
template <>
uint64_t get_time_now<uint64_t>() {
  //   std::cout << "===========2\n";
  std::chrono::steady_clock::time_point n0;
  std::chrono::steady_clock::time_point n1 = std::chrono::steady_clock::now();
  auto dur = std::chrono::duration_cast<std::chrono::nanoseconds>(n1 - n0);
  return dur.count();
}

typedef enum { NS, MS, S } TimeBase;

template <typename T>
T get_use_time(uint64_t ns, TimeBase b) {
  std::chrono::steady_clock::time_point n0;
  std::chrono::steady_clock::time_point n1 = std::chrono::steady_clock::now();
  auto dur = std::chrono::duration_cast<std::chrono::nanoseconds>(n1 - n0);
  float ret;
  switch (b) {
    case NS:
      ret = ((uint64_t)(dur.count()) - ns) / 1.0;
      break;
    case MS:
      ret = (((uint64_t)(dur.count()) - ns) / 1.0) / 1e6;
      break;
    case S:
      ret = (((uint64_t)(dur.count()) - ns) / 1.0) / 1e9;
      break;
    default:
      ret = (((uint64_t)(dur.count()) - ns) / 1.0) / 1e6;
  }
  return T(ret);
}

template <>
float get_use_time(uint64_t ns, TimeBase b) {
  std::chrono::steady_clock::time_point n0;
  std::chrono::steady_clock::time_point n1 = std::chrono::steady_clock::now();
  auto dur = std::chrono::duration_cast<std::chrono::nanoseconds>(n1 - n0);
  float ret = 0.0;
  switch (b) {
    case NS:
      ret = ((uint64_t)(dur.count()) - ns) / 1.0;
      break;
    case MS:
      ret = (((uint64_t)(dur.count()) - ns) / 1.0) / 1e6;
      break;
    case S:
      ret = (((uint64_t)(dur.count()) - ns) / 1.0) / 1e9;
      break;
    default:
      ret = (((uint64_t)(dur.count()) - ns) / 1.0) / 1e6;
  }
  return ret;
}
// }  // namespace utils
#endif