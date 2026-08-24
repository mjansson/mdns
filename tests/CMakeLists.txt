include(FetchContent)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries" FORCE)
set(UNIT_TESTING OFF CACHE BOOL "Build cmocka unit tests" FORCE)
set(WITH_EXAMPLES OFF CACHE BOOL "Build cmocka examples" FORCE)

FetchContent_Declare(
  cmocka
  URL https://cmocka.org/files/1.1/cmocka-1.1.7.tar.xz
  URL_HASH SHA256=810570eb0b8d64804331f82b29ff47c790ce9cd6b163e98d47a4807047ecad82)
FetchContent_MakeAvailable(cmocka)

add_executable(mdns_parse_test mdns_parse_test.c)
target_link_libraries(mdns_parse_test PRIVATE mdns::mdns cmocka::cmocka)
add_test(NAME mdns_parse COMMAND mdns_parse_test)
