cmake_minimum_required(VERSION 3.20)
project(pap_cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Set PAP_ROOT for examples ---
if(NOT PAP_ROOT)
    set(PAP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
    get_filename_component(PAP_ROOT "${PAP_ROOT}" ABSOLUTE)
endif()

# --- Examples subdirectory ---
add_subdirectory(examples)
