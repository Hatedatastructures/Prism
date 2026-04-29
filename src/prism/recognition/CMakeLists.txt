# Recognition 模块构建配置

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            # 基础结构
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/recognition.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/confidence.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/feature.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/result.hpp

            # Probe 外层协议探测子模块
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/probe/probe.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/probe/analyzer.hpp

            # ClientHello 特征检测子模块
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/arrival/feature.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/arrival/registry.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/arrival/reality.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/arrival/ech.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/arrival/anytls.hpp

            # Handshake 执行子模块
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/handshake/priority.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/handshake/executor.hpp
)

target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        # 模块入口
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/recognition.cpp

        # Probe 协议探测实现
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/probe/analyzer.cpp

        # ClientHello 分析器实现
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/arrival/registry.cpp
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/arrival/reality.cpp

        # Handshake 执行器实现
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/handshake/executor.cpp
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/handshake/priority.cpp
)