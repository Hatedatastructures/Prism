target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        connection/pool.cpp
        health.cpp
        eyeball/racer.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/channel/health.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/channel/transport/transmission.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/channel/transport/reliable.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/channel/transport/unreliable.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/channel/transport/encrypted.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/channel/adapter/connector.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/channel/eyeball/racer.hpp
)
