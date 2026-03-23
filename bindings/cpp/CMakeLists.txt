cmake_minimum_required(VERSION 3.20)
project(pap_cpp_example CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Locate libpap_c ---
# Set PAP_ROOT to the repo root, or override PAP_C_LIB / PAP_INCLUDE_DIR.
if(NOT PAP_ROOT)
    set(PAP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
endif()

set(PAP_INCLUDE_DIR "${PAP_ROOT}/crates/pap-c/include"
    CACHE PATH "Directory containing pap.h")
set(PAP_CPP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
    CACHE PATH "Directory containing pap.hpp")

find_library(PAP_C_LIB
    NAMES pap_c
    HINTS "${PAP_ROOT}/target/release"
          "${PAP_ROOT}/target/debug"
    REQUIRED)

message(STATUS "PAP C library : ${PAP_C_LIB}")
message(STATUS "PAP include   : ${PAP_INCLUDE_DIR}")

# --- Example executable ---
add_executable(pap_example example.cpp)

target_include_directories(pap_example PRIVATE
    ${PAP_INCLUDE_DIR}
    ${PAP_CPP_INCLUDE_DIR})

target_link_libraries(pap_example PRIVATE ${PAP_C_LIB})

# On macOS, link CoreFoundation / Security (pulled in by ring via libpap_c)
if(APPLE)
    target_link_libraries(pap_example PRIVATE
        "-framework CoreFoundation"
        "-framework Security")
endif()
