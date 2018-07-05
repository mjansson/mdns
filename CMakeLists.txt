cmake_minimum_required(VERSION 3.0.0)

add_library(mdns STATIC libmdns.c)
add_executable(mdns-example mdns-example.c)
target_link_libraries(mdns-example mdns)
