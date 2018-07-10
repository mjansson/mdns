cmake_minimum_required(VERSION 3.0.0)

add_library(mdns STATIC libmdns.c)
add_executable(mdns-example mdns-example.c)
if (WIN32)
target_link_libraries(mdns-example mdns ws2_32)
else()
target_link_libraries(mdns-example mdns)
endif()