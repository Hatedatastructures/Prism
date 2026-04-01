target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        launch.cpp
        stats.cpp
        tls.cpp
        worker.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/agent/worker/launch.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/worker/stats.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/worker/tls.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/worker/worker.hpp
)
