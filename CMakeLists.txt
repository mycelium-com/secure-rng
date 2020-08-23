cmake_minimum_required(VERSION 3.9)
project(secure-rng VERSION 1.0.0 DESCRIPTION "Secure random generator library")

set(CMAKE_C_FLAGS_ORIG "${CMAKE_C_FLAGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_ORIG} -march=armv8-a+simd+crypto")

try_compile(
    secure_rng_aarch64
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/aarch64/aes.c
    CMAKE_FLAGS
        -DCOMPILE_DEFINITIONS:STRING=${CMAKE_REQUIRED_FLAGS_aarch64}
        -DINCLUDE_DIRECTORIES:STRING=${CMAKE_CURRENT_SOURCE_DIR}/include
    COMPILE_DEFINITIONS
        "-DTRY_COMPILE"
    C_STANDARD_REQUIRED
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_ORIG} -maes")

try_compile(
    secure_rng_x86
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/x86/aes.c
    CMAKE_FLAGS
        -DCOMPILE_DEFINITIONS:STRING=${CMAKE_REQUIRED_FLAGS_x86}
        -DINCLUDE_DIRECTORIES:STRING=${CMAKE_CURRENT_SOURCE_DIR}/include
    COMPILE_DEFINITIONS
        "-DTRY_COMPILE"
    C_STANDARD_REQUIRED
)

if (secure_rng_aarch64)
message(STATUS "Looking for AES support - found armv8 SIMD")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_ORIG} -march=armv8-a+simd+crypto")
add_library(secure-rng src/aarch64/aes.c src/secure-rng.c)
endif()

if (secure_rng_x86)
message(STATUS "Looking for AES support - found intel AES-NI")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_ORIG} -maes")
add_library(secure-rng src/x86/aes.c src/secure-rng.c)
endif()

target_include_directories(secure-rng PRIVATE include)

set_target_properties(secure-rng PROPERTIES
   VERSION ${PROJECT_VERSION}
   POSITION_INDEPENDENT_CODE 1
   PUBLIC_HEADER "include/secure-rng.h"
)

add_executable(bench_rng misc/bench_rng.c $<TARGET_OBJECTS:secure-rng>)
target_include_directories(bench_rng PRIVATE include)
target_link_libraries(bench_rng secure-rng)


include(GNUInstallDirs)
install(TARGETS secure-rng
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(secure-rng.pc.in secure-rng.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/secure-rng.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)