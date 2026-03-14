cmake_minimum_required(VERSION 3.23)
project(forward LANGUAGES CXX)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_PREFIX_PATH "c:/bin")

if(NOT DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "c:/bin")
endif()
set(OPENSSL_USE_STATIC_LIBS TRUE)

find_package(spdlog CONFIG REQUIRED)
find_package(glaze CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

find_package(Boost QUIET COMPONENTS system)
if(NOT TARGET Boost::system)
    set(Boost_NO_BOOST_CMAKE ON)
    find_package(Boost QUIET COMPONENTS system)
endif()

if(NOT TARGET Boost::system)
    find_path(boost_include_dir
            NAMES boost/system/error_code.hpp
            HINTS
            "c:/bin/include"
            "c:/bin"
            PATH_SUFFIXES include
    )

    if(NOT boost_include_dir)
        message(FATAL_ERROR "Could not find the Boost headers required for the build")
    endif()

    message(STATUS "Boost Include Dir: ${boost_include_dir}")

    add_library(boost_system_header_only INTERFACE)
    target_include_directories(boost_system_header_only INTERFACE ${boost_include_dir})
    target_compile_definitions(boost_system_header_only INTERFACE BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_LIB)
    add_library(Boost::system ALIAS boost_system_header_only)
else()
    get_target_property(boost_include_dir Boost::system INTERFACE_INCLUDE_DIRECTORIES)
endif()

enable_testing()

option(FORWARD_ENGINE_ENABLE_BENCHMARK "Enable forward benchmarks" ON)
message(STATUS "FORWARD_ENGINE_ENABLE_BENCHMARK=${FORWARD_ENGINE_ENABLE_BENCHMARK}")

option(FORWARD_ENGINE_ENABLE_STRESS "Enable forward stress tools" ON)
message(STATUS "FORWARD_ENGINE_ENABLE_STRESS=${FORWARD_ENGINE_ENABLE_STRESS}")

add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(benchmarks)
add_subdirectory(stresses)