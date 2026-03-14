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
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/reactor/launch.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/reactor/stats.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/reactor/tls.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/reactor/worker.hpp
)
