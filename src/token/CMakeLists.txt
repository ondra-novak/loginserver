cmake_minimum_required(VERSION 2.8) 
add_compile_options(-std=c++14)
file(GLOB token_SRC "token.cpp" "usertoken.cpp" )
file(GLOB token_HDR "token.h" "usertoken.h")

add_library (token ${token_SRC} )
 
add_executable (token_test test.cpp)
target_link_libraries (token_test LINK_PUBLIC token imtjson crypto)