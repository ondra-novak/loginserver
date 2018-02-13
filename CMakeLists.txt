cmake_minimum_required(VERSION 2.8)
project (loginsrv)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/)

include_directories(BEFORE src/imtjson/src src/couchit/src src src/simpleServer/src)
add_compile_options(-std=c++14)

add_subdirectory (src/imtjson/src/imtjson EXCLUDE_FROM_ALL)
add_subdirectory (src/couchit/src/couchit EXCLUDE_FROM_ALL)
add_subdirectory (src/simpleServer/src/simpleServer EXCLUDE_FROM_ALL)
add_subdirectory (src/simpleServer/src/rpc EXCLUDE_FROM_ALL)
add_subdirectory (src/server)
add_subdirectory (src/session)