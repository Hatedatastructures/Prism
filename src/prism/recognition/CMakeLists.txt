# Recognition 模块构建配置

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            # 基础结构
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/recognition.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/confidence.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/result.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/routes.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/pipeline.hpp

            # TLS 特征分析子模块
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/tls/signal.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/tls/features.hpp

            # 目标地址解析
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/target.hpp

            # Probe 外层协议探测子模块
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/probe/probe.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/probe/analyzer.hpp
)

target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        # 模块入口
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/recognition.cpp

        # SNI 路由表
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/routes.cpp

        # 分层检测管道
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/pipeline.cpp

        # TLS 信号解析
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/tls/signal.cpp

        # 目标地址解析实现
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/target.cpp

        # Probe 协议探测实现
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/probe/analyzer.cpp
)
