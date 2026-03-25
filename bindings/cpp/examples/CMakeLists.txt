cmake_minimum_required(VERSION 3.20)
project(pap_cpp_examples CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Configuration ---
if(NOT PAP_ROOT)
    set(PAP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
endif()

# Normalize PAP_ROOT to absolute path (resolve relative paths)
get_filename_component(PAP_ROOT "${PAP_ROOT}" ABSOLUTE)

set(PAP_INCLUDE_DIR "${PAP_ROOT}/crates/pap-c/include"
    CACHE PATH "Directory containing pap.h")
set(PAP_CPP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.."
    CACHE PATH "Directory containing pap.hpp")

# Locate libpap_c (handles .a on Unix, .lib for static on Windows)
# On Windows, use static library (.lib) which includes all symbols
if(EXISTS "${PAP_ROOT}/target/release/pap_c.lib")
    set(PAP_C_LIB "${PAP_ROOT}/target/release/pap_c.lib")
    message(STATUS "Using static library: ${PAP_C_LIB}")
elseif(EXISTS "${PAP_ROOT}/target/debug/pap_c.lib")
    set(PAP_C_LIB "${PAP_ROOT}/target/debug/pap_c.lib")
elseif(EXISTS "${PAP_ROOT}/target/release/libpap_c.a")
    set(PAP_C_LIB "${PAP_ROOT}/target/release/libpap_c.a")
elseif(EXISTS "${PAP_ROOT}/target/debug/libpap_c.a")
    set(PAP_C_LIB "${PAP_ROOT}/target/debug/libpap_c.a")
else()
    message(FATAL_ERROR "Could not find PAP_C_LIB in ${PAP_ROOT}/target/{release,debug}")
endif()

# Ensure PAP_C_DLL is set for Windows (for copying to build directory)
if(WIN32 AND NOT PAP_C_DLL)
    set(PAP_C_DLL "${PAP_ROOT}/target/release/pap_c.dll")
endif()

message(STATUS "PAP C library       : ${PAP_C_LIB}")
message(STATUS "PAP include (C)     : ${PAP_INCLUDE_DIR}")
message(STATUS "PAP include (C++)   : ${PAP_CPP_INCLUDE_DIR}")

# Add library search path (for linking with .lib files on Windows)
link_directories("${PAP_ROOT}/target/release" "${PAP_ROOT}/target/debug")

# --- Compiler flags ---
# Enable strict warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# --- Examples ---

# basic_flow: Mandate → Session → Receipt flow
add_executable(example_basic_flow basic_flow.cpp)
target_include_directories(example_basic_flow PRIVATE
    ${PAP_INCLUDE_DIR}
    ${PAP_CPP_INCLUDE_DIR})
target_link_libraries(example_basic_flow PRIVATE ${PAP_C_LIB})

if(APPLE)
    target_link_libraries(example_basic_flow PRIVATE
        "-framework CoreFoundation"
        "-framework Security")
elseif(WIN32 AND EXISTS "${PAP_C_DLL}")
    add_custom_command(TARGET example_basic_flow POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${PAP_C_DLL}"
            $<TARGET_FILE_DIR:example_basic_flow>)
endif()

# raii_and_errors: RAII destructor verification and error handling
add_executable(example_raii_and_errors raii_and_errors.cpp)
target_include_directories(example_raii_and_errors PRIVATE
    ${PAP_INCLUDE_DIR}
    ${PAP_CPP_INCLUDE_DIR})
target_link_libraries(example_raii_and_errors PRIVATE ${PAP_C_LIB})

if(APPLE)
    target_link_libraries(example_raii_and_errors PRIVATE
        "-framework CoreFoundation"
        "-framework Security")
elseif(WIN32 AND EXISTS "${PAP_C_DLL}")
    add_custom_command(TARGET example_raii_and_errors POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${PAP_C_DLL}"
            $<TARGET_FILE_DIR:example_raii_and_errors>)
endif()

# delegation_chain: Multi-hop delegation with scope narrowing
add_executable(example_delegation_chain delegation_chain.cpp)
target_include_directories(example_delegation_chain PRIVATE
    ${PAP_INCLUDE_DIR}
    ${PAP_CPP_INCLUDE_DIR})
target_link_libraries(example_delegation_chain PRIVATE ${PAP_C_LIB})

if(APPLE)
    target_link_libraries(example_delegation_chain PRIVATE
        "-framework CoreFoundation"
        "-framework Security")
elseif(WIN32 AND EXISTS "${PAP_C_DLL}")
    add_custom_command(TARGET example_delegation_chain POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${PAP_C_DLL}"
            $<TARGET_FILE_DIR:example_delegation_chain>)
endif()

# --- Tests via ctest ---
# Enable testing
enable_testing()

# Add tests for each example
add_test(
    NAME "basic_flow"
    COMMAND example_basic_flow
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_test(
    NAME "raii_and_errors"
    COMMAND example_raii_and_errors
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_test(
    NAME "delegation_chain"
    COMMAND example_delegation_chain
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Set environment for tests (if needed)
if(APPLE)
    set_tests_properties(
        basic_flow raii_and_errors delegation_chain
        PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${PAP_ROOT}/target/release"
    )
else()
    set_tests_properties(
        basic_flow raii_and_errors delegation_chain
        PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${PAP_ROOT}/target/release"
    )
endif()

# Print summary
message(STATUS "")
message(STATUS "=== C++ Examples & Tests ===")
message(STATUS "  example_basic_flow          : Mandate → Session → Receipt flow")
message(STATUS "  example_raii_and_errors     : RAII destructors and error handling")
message(STATUS "  example_delegation_chain    : Multi-hop delegation")
message(STATUS "")
message(STATUS "Run with: ctest --output-on-failure")
message(STATUS "Or run individual examples directly:")
message(STATUS "  ./example_basic_flow")
message(STATUS "  ./example_raii_and_errors")
message(STATUS "  ./example_delegation_chain")
message(STATUS "")
