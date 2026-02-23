cmake_minimum_required(VERSION 3.15)

project(forward_engine_test_server_v1 LANGUAGES CXX)

# 源文件
add_executable(server_v1
    server.cpp
    server.hpp
    api.hpp
    conversation.hpp
    error.hpp
    handler.hpp
    mime.hpp
)

# 包含路径
target_include_directories(server_v1 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    "c:/bin/include"
)

# 设置 C++23 标准
set_target_properties(server_v1 PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

# 链接库
target_link_libraries(server_v1 PRIVATE
    Forward_static_library
    Boost::system
    glaze::glaze
    spdlog::spdlog
    ws2_32
    crypt32
    mswsock
)

# 编译选项
if(MSVC)
    target_compile_options(server_v1 PRIVATE /W4 /O2 /DNDEBUG)
else()
    target_compile_options(server_v1 PRIVATE -Wall -Wextra -O2 -DNDEBUG)
endif()
