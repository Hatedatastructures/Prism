cmake_minimum_required(VERSION 3.15)

# headers 测试可执行程序
add_executable(headers_test
        header.cpp
)

target_link_libraries(headers_test
        PRIVATE
        ${PROJECT_NAME}_static_library
)

add_executable(main_test
        main_test.cpp
)

target_compile_options(main_test PRIVATE
        -g1
        -O1
        -fno-keep-inline-dllexport
        -fno-function-sections
        -fno-data-sections
)

target_link_libraries(main_test
        PRIVATE
        ${PROJECT_NAME}_static_library
)


add_test(NAME main_test COMMAND main_test)

add_test(NAME headers_test COMMAND headers_test)

add_executable(json_test
        json_test.cpp
)

target_link_libraries(json_test
        PRIVATE
        ${PROJECT_NAME}_static_library
)

add_test(NAME json_test COMMAND json_test)

# request 测试可执行程序
add_executable(request_test
        request.cpp
)

target_link_libraries(request_test
        PRIVATE
        ${PROJECT_NAME}_static_library
)

add_executable(glaze_test
    glaze_test.cpp
)

target_link_libraries(glaze_test
        PRIVATE
        ${PROJECT_NAME}_static_library
)

add_test(NAME glaze_test COMMAND glaze_test)

add_test(NAME request_test COMMAND request_test)

# 日志模块测试可执行程序
add_executable(log_test
        log.cpp
)

target_link_libraries(log_test
        PRIVATE
        ${PROJECT_NAME}_static_library
)

add_test(NAME log_test COMMAND log_test)

# session 测试可执行程序
add_executable(session_test
        session.cpp
)

# 仅保留解决.obj体积的关键选项，无任何多余参数
target_compile_options(session_test PRIVATE
        -g1          # 降低调试信息级别，减小.obj体积
        -O1          # 轻度优化，折叠重复模板代码
        -fno-keep-inline-dllexport # 辅助减少冗余符号（可选）
)

# 链接阶段无需加任何额外参数，删掉所有-Wl,--large-address-aware
# target_link_options(session_test PRIVATE ...)  # 清空这部分错误配置

target_link_libraries(session_test
        PRIVATE
        ${PROJECT_NAME}_static_library

)

add_test(NAME session_test COMMAND session_test)

# obscura 测试可执行程序
add_executable(obscura_test_exec
        obscura.cpp
)

target_compile_options(obscura_test_exec PRIVATE
          -O2
          -fno-keep-inline-dllexport
          -Wa,-mbig-obj
  )

target_link_libraries(obscura_test_exec
        PRIVATE
        ${PROJECT_NAME}_static_library
)

add_test(NAME obscura_test COMMAND obscura_test_exec)

# connection 测试可执行程序
add_executable(connection_test
        connection_test.cpp
)

target_link_libraries(connection_test
        PRIVATE
        ${PROJECT_NAME}_static_library
)

add_test(NAME connection_test COMMAND connection_test)

# spdlog 测试可执行程序
add_executable(spdlog_test
        spdlog_test.cpp
)

target_link_libraries(spdlog_test
        PRIVATE
        ${PROJECT_NAME}_static_library
)

add_test(NAME spdlog_test COMMAND spdlog_test)

# SOCKS5 测试
add_executable(socks5_test socks5_test.cpp)
target_compile_options(socks5_test PRIVATE -g1 -Os -fno-keep-inline-dllexport)
target_link_libraries(socks5_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME socks5_test COMMAND socks5_test)

# Trojan 测试
add_executable(trojan_test trojan_test.cpp)
target_compile_options(trojan_test PRIVATE -g1 -Os -fno-keep-inline-dllexport)
target_link_libraries(trojan_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME trojan_test COMMAND trojan_test)

if (MINGW)
    foreach(target_name IN ITEMS headers_test main_test json_test request_test glaze_test log_test session_test obscura_test_exec connection_test spdlog_test socks5_test trojan_test)
        if (TARGET ${target_name})
            target_compile_options(${target_name} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()
