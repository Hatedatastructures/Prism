target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        monitor.cpp
        spdlog.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/trace.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/trace/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/trace/monitor.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/trace/spdlog.hpp
)
