cmake_minimum_required(VERSION 3.5)
project(mdns VERSION 1.4.2 LANGUAGES C)

option(MDNS_BUILD_EXAMPLE "build example" ON)
set(MDNS_IS_TOP_LEVEL OFF)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(MDNS_IS_TOP_LEVEL ON)
endif()
option(MDNS_BUILD_TESTS "build tests" ${MDNS_IS_TOP_LEVEL})

# Set the output of the libraries and executables.
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

# ##############################################################################
# library
# ##############################################################################

include(GNUInstallDirs)

add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(
  ${PROJECT_NAME} INTERFACE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/>
                            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
if(WIN32)
  target_link_libraries(${PROJECT_NAME} INTERFACE iphlpapi ws2_32)
endif()
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
target_compile_features(${PROJECT_NAME} INTERFACE c_std_99)

# ##############################################################################
# example
# ##############################################################################

if(MDNS_BUILD_EXAMPLE)
  add_executable(${PROJECT_NAME}_example mdns.c)
  target_link_libraries(${PROJECT_NAME}_example ${PROJECT_NAME})
endif()

# ##############################################################################
# tests
# ##############################################################################

if(MDNS_BUILD_TESTS)
  enable_testing()
  add_executable(${PROJECT_NAME}_test_string_compression
                 test/test_string_compression.c)
  target_link_libraries(${PROJECT_NAME}_test_string_compression ${PROJECT_NAME})
  add_test(NAME string_compression
           COMMAND ${PROJECT_NAME}_test_string_compression)
endif()

# ##############################################################################
# install
# ##############################################################################

install(
  TARGETS ${PROJECT_NAME}
  EXPORT ${PROJECT_NAME}_Targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

include(CMakePackageConfigHelpers)
if(${CMAKE_VERSION} VERSION_LESS 3.14)
  write_basic_package_version_file(
    "${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
else()
  write_basic_package_version_file(
    "${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT)
endif()

configure_package_config_file(
  "${PROJECT_SOURCE_DIR}/cmake/Config.cmake.in"
  "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake" INSTALL_DESTINATION
  ${CMAKE_INSTALL_DATAROOTDIR}/cmake/${PROJECT_NAME})

install(
  EXPORT ${PROJECT_NAME}_Targets
  FILE ${PROJECT_NAME}Targets.cmake
  NAMESPACE ${PROJECT_NAME}::
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cmake/${PROJECT_NAME})

install(FILES "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
              "${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cmake/${PROJECT_NAME})

install(FILES "${PROJECT_SOURCE_DIR}/mdns.h" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
