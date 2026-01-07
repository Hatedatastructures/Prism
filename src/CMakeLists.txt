# 收集库源文件
set(FORWARD_LIB_SOURCES
        forward-engine/http/header.cpp
        ../include/forward-engine/http/header.hpp
        forward-engine/http/request.cpp
        ../include/forward-engine/http/request.hpp
        forward-engine/trace/monitor.cpp
        ../include/forward-engine/trace/monitor.hpp
        forward-engine/http/response.cpp
        ../include/forward-engine/http/response.hpp
        forward-engine/http/serialization.cpp
        ../include/forward-engine/http/serialization.hpp
        forward-engine/http/deserialization.cpp
        ../include/forward-engine/http/deserialization.hpp
        forward-engine/agent/positive.cpp
        ../include/forward-engine/agent/positive.hpp
        forward-engine/agent/reverse.cpp
        ../include/forward-engine/agent/reverse.hpp
        forward-engine/agent/frame.cpp
        ../include/forward-engine/agent/frame.hpp
        forward-engine/agent/distributor.cpp
        ../include/forward-engine/agent/distributor.hpp
        forward-engine/agent/connection.cpp
        ../include/forward-engine/agent/connection.hpp
        ../include/forward-engine/agent/obscura.hpp
        ../include/forward-engine/agent/session.hpp
        ../include/forward-engine/rule/blacklist.hpp
        ../include/forward-engine/http.hpp
        ../include/forward-engine/http/constants.hpp
        ../include/forward-engine/core/broker.hpp
        ../include/forward-engine/agent.hpp
        ../include/forward-engine/agent/worker.hpp
        forward-engine/rule/blacklist.cpp
        ../include/forward-engine/memory/pointer.hpp
        ../include/forward-engine/agent/adaptation.hpp
        ../include/forward-engine/agent/analysis.hpp
        forward-engine/agent/analysis.cpp
        ../include/forward-engine/memory/container.hpp
        ../include/forward-engine/abnormal/deviant.hpp
        ../include/forward-engine/abnormal/security.hpp
        ../include/forward-engine/abnormal/network.hpp
        ../include/forward-engine/abnormal/protocol.hpp
        ../include/forward-engine/abnormal.hpp
        ../include/forward-engine/core/configuration.hpp
        ../include/forward-engine/trace/spdlog.hpp
        forward-engine/trace/spdlog.cpp
        ../include/forward-engine/trace.hpp
        ../include/forward-engine/rule.hpp
        ../include/forward-engine/transformer.hpp
        ../include/forward-engine/transformer/json.hpp
        ../include/forward-engine/agent/config.hpp
        ../include/forward-engine/trace/config.hpp
        ../include/forward-engine/rule/config.hpp
        ../include/forward-engine/memory/pool.hpp
        ../include/forward-engine/memory.hpp
)

# 创建静态库
add_library(${PROJECT_NAME}_static_library STATIC
        ${FORWARD_LIB_SOURCES}
)

# 设置目标属性
target_include_directories(${PROJECT_NAME}_static_library
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/forward-engine
        ${boost_include_dir}
        ${Boost_INCLUDE_DIRS}
)

# spdlog 集成
find_package(spdlog CONFIG REQUIRED)

# 链接依赖
target_link_libraries(${PROJECT_NAME}_static_library
        PUBLIC
        async_simple::async_simple
        spdlog::spdlog
        glaze::glaze
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
        ws2_32
        mswsock
        crypt32
)

target_compile_definitions(${PROJECT_NAME}_static_library
        PUBLIC
        BOOST_ASIO_HEADER_ONLY
)

# 创建可执行程序
add_executable(${PROJECT_NAME}
        main.cpp
)

target_compile_options(${PROJECT_NAME} PRIVATE
        -g1          # 降低调试信息级别，减小.obj体积
        -O1          # 轻度优化，折叠重复模板代码
        -fno-keep-inline-dllexport # 辅助减少冗余符号（可选）
)


target_link_libraries(${PROJECT_NAME}
        PRIVATE
        ${PROJECT_NAME}_static_library
)
