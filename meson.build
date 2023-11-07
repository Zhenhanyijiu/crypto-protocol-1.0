project('crypto-protocal', 'cpp',
  version: '0.0.1',
  default_options: [
    'buildtype=debug',
    #'buildtype=release',
    'default_library=static',
    'cpp_std=c++14',
    'warning_level=3'],
  meson_version: '>=1.0.0')

#vcpkg = find_program('vcpkg', required : true)
#run_command(vcpkg, 'install',
#  '--x-wait-for-lock',
#  '--x-manifest-root=' + meson.current_source_dir(),
#  '--x-install-root=/root/github/vcpkg/installed',
#  check: true)

includes = include_directories(
  '.',
#   '/usr/include/',
  './thirdparty/cryptoTools',
#   'include/bloom_filter',
#   'include/core/io',
#   'include/core/utils',
#   'include/core/network',
#   'include/utils_inc',
#   'include/third_party',
#   'include/third_party/base',
#   'include/third_party/inc_botan',
#   'include/third_party/inc_ntl',
)
# -msse3 -msse2 -msse4.1 -maes -mpclmul
crypto_compile_args = [
  '-Wno-pedantic',
  '-Wno-sign-compare',
  '-Wno-unused-parameter',
  '-Wno-ignored-qualifiers',
  # FIXME
  '-Wno-switch',
  '-Wno-attributes', # llvm enum_extensibility, macoro/coro_frame.h
#   '-DCOPROTO_ENABLE_BOOST',
'-msse3',
'-msse2',
'-msse4.1',
'-maes',
'-mpclmul',
]

# absl_dep = dependency('absl', modules: ['absl::base', 'absl::variant', 'absl::strings'])
# boring_dep = dependency('openssl') # pkgconf是根据文件名的区分的(openssl.pc), 而不是pc文件中的Name字段(Name: BoringSSL)
openssl_dep = dependency('openssl') # pkgconf是根据文件名的区分的(openssl.pc), 而不是pc文件中的Name字段(Name: BoringSSL)
blake3_dep = dependency('blake3') # 
# thread_dep = dependency('threads')
spdlog_dep = dependency('spdlog')
cereal_dep = dependency('cereal')
# gmp_dep = dependency('gmp')
# boost_dep = dependency('boost', modules: ['serialization']) # 系统路径找, vcpkg安装这里用不了
# botan_dep = dependency('botan-2')
# ntl_dep = dependency('ntl') # 自定义的pc文件 /root/vcpkg/installed/x64-linux/lib/pkgconfig/ntl.pc
# coproto_dep = dependency('coproto')

crypto_dependencies = []
# crypto_dependencies += absl_dep
crypto_dependencies += openssl_dep
crypto_dependencies += blake3_dep
# crypto_dependencies += thread_dep
crypto_dependencies += spdlog_dep
crypto_dependencies += cereal_dep
# crypto_dependencies += gmp_dep
# crypto_dependencies += boost_dep
# crypto_dependencies += botan_dep
# crypto_dependencies += ntl_dep
# crypto_dependencies += coproto_dep

subdir('src')
subdir('tests')
# subdir('pybind')
# subdir('pybind_ks')
