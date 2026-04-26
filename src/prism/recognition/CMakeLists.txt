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

            # ClientHello 特征检测子模块
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/clienthello/analyzer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/clienthello/registry.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/clienthello/reality.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/clienthello/ech.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/clienthello/anytls.hpp

            # Handshake 执行子模块
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/handshake/priority.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/handshake/executor.hpp
)

target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        # 模块入口
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/recognition.cpp

        # ClientHello 分析器实现
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/clienthello/registry.cpp
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/clienthello/reality.cpp

        # Handshake 执行器实现
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/handshake/executor.cpp
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/handshake/priority.cpp
)