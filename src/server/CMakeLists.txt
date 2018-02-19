cmake_minimum_required(VERSION 2.8) 
add_compile_options(-std=c++14)
file(GLOB server_SRC "*.cpp" )
file(GLOB server_HDR "*.h" "*.tcc")

add_executable (loginsrv ${server_SRC} )
target_link_libraries (loginsrv LINK_PUBLIC token gatotp simpleRpcServer simpleServer couchit imtjson crypto pthread)
install(TARGETS loginsrv DESTINATION "bin") 
 