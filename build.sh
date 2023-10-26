CURR_PATH=${PWD}
echo -e "=== CURR_PATH:${CURR_PATH}\n"
compile_and_run_make(){
cd $CURR_PATH
if [ -d "build" ];then
    rm -rf build
fi
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=${CURR_PATH}/out \
-DCMAKE_PREFIX_PATH=${CURR_PATH}/out -DCMAKE_BUILD_TYPE=Debug
# cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j16
cmake --install build
}

# compile_and_run_make
export PATH=${PATH}:/usr/local/python3/bin
compile_and_run_ninja(){
cd $CURR_PATH
if [ -d "build" ];then
    rm -rf build
fi
cmake -S . -B build -G Ninja -DCMAKE_INSTALL_PREFIX=${CURR_PATH}/out \
-DCMAKE_PREFIX_PATH=${CURR_PATH}/out -DCMAKE_BUILD_TYPE=Debug
# cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j16
cmake --install build
}
compile_and_run_ninja