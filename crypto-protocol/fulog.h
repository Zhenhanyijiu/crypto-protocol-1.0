#ifndef __FU_TOOLS_SPD_LOG_H__
#define __FU_TOOLS_SPD_LOG_H__
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE

#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <string>
#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

extern void spdlog_set_level(std::string level);
// }  // namespace utils
#if defined(__cplusplus) || defined(c_plusplus)
}
#endif
#endif