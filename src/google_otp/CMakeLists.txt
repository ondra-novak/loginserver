cmake_minimum_required(VERSION 2.8) 
add_compile_options(-std=c++14)
file(GLOB gatotp_SRC "ga.cpp" "base32.cpp"  )
file(GLOB gatotp_HDR "ga.h" )

add_library (gatotp ${gatotp_SRC} )
 