cmake_minimum_required(VERSION 3.15)
project(Forward LANGUAGES CXX)

cmake_policy(SET CMP0167 NEW)


# 全局设置
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 依赖管理
list(APPEND CMAKE_PREFIX_PATH "c:/bin")

if(NOT DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "c:/bin")
endif()
set(OPENSSL_USE_STATIC_LIBS TRUE)

find_package(async_simple CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
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
        message(FATAL_ERROR "找不到 `boost` 头文件目录，无法继续构建")
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

# 添加子目录
add_subdirectory(src)
add_subdirectory(test)

