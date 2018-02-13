cmake_minimum_required(VERSION 2.8) 
add_compile_options(-std=c++14)
file(GLOB session_SRC "*.cpp" )
file(GLOB session_HDR "*.h" "*.tcc")

add_library (session ${session_SRC} )
 
 