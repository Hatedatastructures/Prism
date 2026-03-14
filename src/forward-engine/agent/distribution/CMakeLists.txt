target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        reliable.cpp
        datagram.cpp
        router.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/distribution/arbiter.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/distribution/coalescer.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/distribution/datagram.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/distribution/reliable.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/distribution/router.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/distribution/transparent.hpp
)
