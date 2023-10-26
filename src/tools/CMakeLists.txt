message(STATUS "== in tools dir")
message(STATUS "== CMAKE_SOURCE_DIR        :${CMAKE_SOURCE_DIR}")
message(STATUS "== CMAKE_CURRENT_SOURCE_DIR:${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "== PROJECT_SOURCE_DIR      :${PROJECT_SOURCE_DIR}")
message(STATUS "== PROJECT_BINARY_DIR      :${PROJECT_BINARY_DIR}")
message(STATUS "== CMAKE_MODULE_PATH       :${CMAKE_MODULE_PATH}")
message(STATUS "== CMAKE_BUILD_TYPE        :${CMAKE_BUILD_TYPE}")
message(STATUS "== CMAKE_CXX_FLAGS         :${CMAKE_CXX_FLAGS}")

if(DEBUG_TOOLS_TCPSOCKET_EXE)
    add_executable(tcpsocket_exe ${PROJECT_SOURCE_DIR}/tools/tcpsocket.cpp)
    target_compile_definitions(tcpsocket_exe PUBLIC DEBUG_TCPSOCKET)

    # target_compile_options(server_exe PUBLIC -fpic)
    target_include_directories(tcpsocket_exe PUBLIC
        # ${Boost_INCLUDE_DIR}
        # ${WEBSOCKETPP_INCLUDE_DIR}
        # ${PROJECT_SOURCE_DIR}/libdev/include
        ${PROJECT_SOURCE_DIR}
    )

    # target_link_directories(server_exe PUBLIC ${PROJECT_SOURCE_DIR}/libdev/lib)
    target_link_libraries(tcpsocket_exe PUBLIC
        # boost_system boost_thread
        # pthread
    )
    set_target_properties(tcpsocket_exe
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
    )
    install(TARGETS tcpsocket_exe DESTINATION bin)
    # install(TARGETS ${PROJECT_SOURCE_DIR}/tools/*.h DESTINATION include)
endif(DEBUG_TOOLS_TCPSOCKET_EXE)

# buffersocket
if(DEBUG_TOOLS_BUFFER_SOCKET_EXE)
    add_executable(buffersocket_exe 
    ${PROJECT_SOURCE_DIR}/tools/buffersocket.cpp
    ${PROJECT_SOURCE_DIR}/tools/tcpsocket.cpp
    ${PROJECT_SOURCE_DIR}/tools/fulog.cpp
    )
    target_compile_definitions(buffersocket_exe PUBLIC DEBUG_BUFFER_SOCKET)
    target_include_directories(buffersocket_exe PUBLIC      
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/out/include
    )

    target_link_libraries(buffersocket_exe PUBLIC
        # boost_system boost_thread
        pthread
    )
    set_target_properties(buffersocket_exe
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
    )
    install(TARGETS buffersocket_exe DESTINATION bin)    
endif(DEBUG_TOOLS_BUFFER_SOCKET_EXE)
