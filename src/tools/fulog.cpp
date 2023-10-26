#include "crypto-protocol/fulog.h"
// namespace utils {

void spdlog_set_level(std::string level) {
  //   auto console = spdlog::stdout_color_mt("dialer");
  if (level == "debug" || level == "DEBUG") {
    spdlog::set_level(spdlog::level::debug);
    // console->set_level(spdlog::level::debug);
  }
  if (level == "info" || level == "INFO") {
    spdlog::set_level(spdlog::level::info);
    // console->set_level(spdlog::level::info);
  }
  if (level == "warn" || level == "WARN") {
    spdlog::set_level(spdlog::level::warn);
    // console->set_level(spdlog::level::info);
  }
  if (level == "error" || level == "ERROR") {
    spdlog::set_level(spdlog::level::err);
    // console->set_level(spdlog::level::err);
  }
  //   spdlog::set_default_logger(console);

  //   auto rotating_logger = spdlog::rotating_logger_mt("SPDLOG_NAME",
  //   "./log.log",
  //                                                     1024 * 1024 * 1,
  //                                                     3);
  // spdlog::default_logger
  //   auto console = spdlog::stdout_color_mt("dialer");
  //   console->set_level(spdlog::level::debug);
  //   spdlog::set_default_logger(console);
  //   SPDLOG_LOGGER_ERROR(console, ">>!!~dialer()");
  //   auto logger = spdlog::daily_logger_mt("daily_logger", "./daily.txt", 2,
  //   30);
}
// }  // namespace utils