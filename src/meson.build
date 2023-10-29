source_files = files(
  'tools/buffersocket.cpp',
  'tools/fulog.cpp',
  'tools/tcpsocket.cpp',
  'hash/hasherimpl.cpp',
  'ecc/eccopenssl.cpp',  
  'ecc/fuecc_open.cpp',  
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
