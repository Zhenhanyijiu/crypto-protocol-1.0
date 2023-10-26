INSTALL_PATH=$1
Code_PATH=$2
cmd_param=$3
DEP_PATH=${Code_PATH}/dep
echo -e " ------- INSTALL_PATH:$INSTALL_PATH"
echo -e " ------- Code_PATH   :$Code_PATH"
echo -e " ------- DEP_PATH    :$DEP_PATH"
echo -e " ------- cmd_param   :$cmd_param"
pwd
if [ ! -d ${DEP_PATH} ];then
    echo "${DEP_PATH} not exist"
    mkdir ${DEP_PATH}
else
    echo "${DEP_PATH} exist"
fi
ls -al ${DEP_PATH}
compile_spdlog_cmd(){
    echo "=========== compile_spdlog_cmd start =========="
    cd ${DEP_PATH} && pwd
    if [ ! -d "spdlog" ];then
        git clone https://github.com/gabime/spdlog.git
    fi
    if [ ! -d "spdlog" ];then
        exit
    else
        cd spdlog 
        git reset --hard 60f5cb73a88ea4e2ee6ee3e5a6431bd6549d6484
    fi
    # if [ ! -d "${CURR_PATH}/libdev/include/spdlog" ];then
    cd ${DEP_PATH}/spdlog
    if [ -d "build" ];then
        rm -rf build
    fi    
    # cmake -DCMAKE_INSTALL_PREFIX=${CURR_PATH}/libdev -DSPDLOG_BUILD_PIC=ON
    cmake -S . -B build -DCMAKE_INSTALL_PREFIX=${INSTALL_PATH} -DSPDLOG_BUILD_PIC=ON
    cmake --build build -j16 && cmake --install build
    # fi    
    cd ${DEP_PATH}
    echo "=========== compile_spdlog_cmd end =========="
}
run_install(){
    echo -e " ------- INSTALL_PATH:$INSTALL_PATH"
    echo -e " ------- Code_PATH   :$Code_PATH"
    echo -e " ------- DEP_PATH    :$DEP_PATH"
    echo -e " ------- cmd_param   :$cmd_param"
    if [ "${cmd_param}" = "boost" ];then
        # compile_boost_cmd
        echo ""
    fi
    if [ "${cmd_param}" = "spdlog" ];then
        compile_spdlog_cmd
    fi
    if [ "${cmd_param}" = "rapidjson" ];then
        # compile_rapidjson_cmd
        echo ""
    fi
    if [ "${cmd_param}" = "websocketpp" ];then
        # git_clone_websocketpp_cmd
        echo ""
    fi

    if [ "${cmd_param}" = "uwebsocket" ];then
        # git_clone_uwebsocket_cmd
        echo ""
    fi

    if [ "${cmd_param}" = "all" ];then
        # compile_boost_cmd
        compile_spdlog_cmd
        # compile_rapidjson_cmd
        # git_clone_websocketpp_cmd
        # git_clone_uwebsocket_cmd
    fi
}
run_install
exit