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
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/scheme_route_table.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/layered_pipeline.hpp

            # Probe 外层协议探测子模块
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/probe/probe.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/recognition/probe/analyzer.hpp
)

target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        # 模块入口
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/recognition.cpp

        # SNI 路由表
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/scheme_route_table.cpp

        # 分层检测管道
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/layered_pipeline.cpp

        # Probe 协议探测实现
        ${PROJECT_SOURCE_DIR}/src/prism/recognition/probe/analyzer.cpp
)
