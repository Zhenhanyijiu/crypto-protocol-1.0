cmake_minimum_required(VERSION 3.16)
project(crypto_protocol)

# Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "== CMAKE_BUILD_TYPE:${CMAKE_BUILD_TYPE}")
set(CMAKE_CXX_STANDARD 11)
# 控制 CMAKE_INSTALL_PREFIX 安装路径
option(INSTALL_USR_LOCAL "need install usr/local default off" OFF)
message(STATUS "Option: INSTALL_USR_LOCAL  = ${INSTALL_USR_LOCAL}")
message(STATUS "== [not set] CMAKE_INSTALL_PREFIX:${CMAKE_INSTALL_PREFIX}")
# INSTALL_USR_LOC 控制要不要安装到默认系统路径
if(NOT INSTALL_USR_LOCAL)
    message(STATUS "== here, not install /usr/local")
    if(${CMAKE_INSTALL_PREFIX} STREQUAL "/usr/local")
        file(MAKE_DIRECTORY ${PROJECT_SOURCE_DIR}/out)
        set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/out)
    endif()
else()
    message(STATUS "== here, install /usr/local")
    if(${CMAKE_INSTALL_PREFIX} STREQUAL "/usr/local")
    else()
        set(CMAKE_INSTALL_PREFIX "/usr/local")
    endif()
endif()
message(STATUS "== [after set] CMAKE_INSTALL_PREFIX:${CMAKE_INSTALL_PREFIX}")
# 全局的
# set(CMAKE_POSITION_INDEPENDENT_CODE ON)
message(STATUS "CMAKE_SOURCE_DIR        :${CMAKE_SOURCE_DIR}")
message(STATUS "CMAKE_CURRENT_SOURCE_DIR:${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "PROJECT_SOURCE_DIR      :${PROJECT_SOURCE_DIR}")
message(STATUS "PROJECT_BINARY_DIR      :${PROJECT_BINARY_DIR}")
message(STATUS "CMAKE_MODULE_PATH       :${CMAKE_MODULE_PATH}")
message(STATUS "CMAKE_BUILD_TYPE        :${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_CXX_FLAGS         :${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_BINARY_DIR        :${CMAKE_BINARY_DIR}")
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${CMAKE_INSTALL_PREFIX})
message(STATUS "== CMAKE_PREFIX_PATH:${CMAKE_PREFIX_PATH}")

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
# message("x86_64")
# set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -msse3 -msse2 -msse4.1 -maes -mpclmul")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm64")
    # message("arm64")
    # set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+simd+crypto+crc")
endif()

find_package(spdlog)

if(spdlog_FOUND)
    message(STATUS "== spdlog_FOUND ok")
else()
    message(WARNING "== spdlog_FOUND not ok")
    execute_process(
        COMMAND sh -c "${PROJECT_SOURCE_DIR}/build_dep.sh ${CMAKE_INSTALL_PREFIX} ${PROJECT_SOURCE_DIR} spdlog"
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    )
endif(spdlog_FOUND)

if(NOT spdlog_FOUND)
    find_package(spdlog)
endif()


message(STATUS "== CMAKE_SYSTEM_PROCESSOR:${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "== CMAKE_CXX_FLAGS       :${CMAKE_CXX_FLAGS}")
message(STATUS "================ add_subdirectory ==============")

option(DEBUG_TOOLS_TCPSOCKET_EXE "debug tools tcpsocket exe" ON)
message(STATUS "Option: DEBUG_TOOLS_TCPSOCKET_EXE  = ${DEBUG_TOOLS_TCPSOCKET_EXE}")
option(DEBUG_TOOLS_BUFFER_SOCKET_EXE "debug tools tcpsocket exe" ON)
message(STATUS "Option: DEBUG_TOOLS_BUFFER_SOCKET_EXE  = ${DEBUG_TOOLS_BUFFER_SOCKET_EXE}")


add_subdirectory(tools)

# file(GLOB_RECURSE TOOLS_HEAD *.h)
file(GLOB TOOLS_HEAD "crypto-protocol/*.h")
# message(STATUS "TOOLS_HEAD:" ${TOOLS_HEAD})
# file(GLOB TOOLS_HEAD *.h)
install(FILES ${TOOLS_HEAD} DESTINATION include/crypto-protocol)
# install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/crynet DESTINATION include)