source_files = files(
    # thirdparty
  '../thirdparty/cryptoTools/cryptoTools/Common/BitVector.cpp',
  '../thirdparty/cryptoTools/cryptoTools/Common/CLP.cpp',
  '../thirdparty/cryptoTools/cryptoTools/Common/Defines.cpp',
  '../thirdparty/cryptoTools/cryptoTools/Common/Log.cpp',
  '../thirdparty/cryptoTools/cryptoTools/Common/TestCollection.cpp',
  '../thirdparty/cryptoTools/cryptoTools/Common/Timer.cpp',
  '../thirdparty/cryptoTools/cryptoTools/Common/tools.cpp',
  '../thirdparty/cryptoTools/cryptoTools/Crypto/AES.cpp',
  '../thirdparty/cryptoTools/cryptoTools/Crypto/PRNG.cpp',
    # 
  'tools/buffersocket.cpp',
  'tools/fulog.cpp',
  'tools/tcpsocket.cpp',
  'hash/hasherimpl.cpp',
  'ecc/eccopenssl.cpp',  
  'ecc/fuecc_open.cpp',  
  'ecc/fuecc.cpp',
  'ot/ot_base.cpp',
  'ot/ot_iknp.cpp',  
)

crypto_lib = library('crypto_protocol',
  source_files,
  include_directories: includes,
  cpp_args: crypto_compile_args,
  dependencies: crypto_dependencies)

crypto_dep = declare_dependency(
  include_directories: includes,
  link_with: crypto_lib,
  dependencies: crypto_dependencies)

crypto_dependencies +=crypto_dep
