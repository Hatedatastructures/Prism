target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        pool/pool.cpp
        health.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/channel/health.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/channel/transport/transmission.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/channel/transport/reliable.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/channel/transport/unreliable.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/channel/transport/encrypted.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/channel/adapter/connector.hpp
)
