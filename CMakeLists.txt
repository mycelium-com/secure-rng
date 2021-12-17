cmake_minimum_required(VERSION 3.9)
project(secure-rng VERSION 1.0.0 DESCRIPTION "Secure random generator library")

try_compile(
    secure_rng_aarch64
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/aarch64/aes.c
    CMAKE_FLAGS "-DCOMPILE_DEFINITIONS:STRING=${CMAKE_REQUIRED_FLAGS_aarch64}"
    COMPILE_DEFINITIONS "-DTRY_COMPILE -DHARDWARE_SUPPORT -DSOFTWARE_FALLBACK -march=armv8-a+simd+crypto -I${CMAKE_CURRENT_SOURCE_DIR}/include"
    C_STANDARD_REQUIRED false
)

try_compile(
    secure_rng_x86
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/x86/aes.c
    CMAKE_FLAGS "-DCOMPILE_DEFINITIONS:STRING=${CMAKE_REQUIRED_FLAGS_x86}"
    COMPILE_DEFINITIONS "-DTRY_COMPILE -DHARDWARE_SUPPORT -DSOFTWARE_FALLBACK -I${CMAKE_CURRENT_SOURCE_DIR}/include"
    C_STANDARD_REQUIRED false
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

if (secure_rng_aarch64)
    message(STATUS "Looking for AES support by compiler - found armv8 SIMD")
    add_library(secure-rng src/generic/aes.c src/aarch64/aes.c src/aarch64/detect.cpp src/secure-rng.c)
    target_compile_options(secure-rng PRIVATE -march=armv8-a+simd+crypto -Os -DHARDWARE_SUPPORT -DSOFTWARE_FALLBACK)
endif()

if (secure_rng_x86)
    message(STATUS "Looking for AES support by compiler - found intel AES-NI")
    add_library(secure-rng src/generic/aes.c src/x86/aes.c src/x86/detect.cpp src/secure-rng.c)
    target_compile_options(secure-rng PRIVATE -maes -O3 -DHARDWARE_SUPPORT -DSOFTWARE_FALLBACK)
endif()

if (NOT secure_rng_aarch64 AND NOT secure_rng_x86)
    message(STATUS "Looking for AES support by compiler - no hardware extensions available for target platform, will be using software implementation only")
    add_library(secure-rng src/generic/aes.c src/secure-rng.c)
    target_compile_options(secure-rng PRIVATE -Os -DSOFTWARE_FALLBACK)
endif()

target_include_directories(secure-rng PRIVATE include)

set_target_properties(secure-rng PROPERTIES
   VERSION ${PROJECT_VERSION}
   POSITION_INDEPENDENT_CODE 1
   PUBLIC_HEADER "include/secure-rng.h"
)

if (BUILD_BENCH)
    message(${secure_rng_aarch64})
    add_executable(bench_rng misc/bench_rng.c)
    target_include_directories(bench_rng PRIVATE include)
    target_link_libraries(bench_rng secure-rng)

    add_executable(bench_pr_rng misc/bench_pr_rng.c)
    target_include_directories(bench_pr_rng PRIVATE include)
    target_link_libraries(bench_pr_rng secure-rng)
endif()

if (BUILD_TEST)
    add_executable(test_rng misc/test_rng.c)
    target_include_directories(test_rng PRIVATE include)
    target_link_libraries(test_rng secure-rng)

    add_executable(test_pr_rng misc/test_pr_rng.c)
    target_include_directories(test_pr_rng PRIVATE include)
    target_link_libraries(test_pr_rng secure-rng)
endif()

include(GNUInstallDirs)
install(TARGETS secure-rng
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(secure-rng.pc.in secure-rng.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/secure-rng.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
