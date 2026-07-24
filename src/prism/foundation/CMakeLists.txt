target_sources(${PROJECT_NAME}_static_library
        PRIVATE
            coroutine/registry.cpp
            rate/counter.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/foundation.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/memory/container.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/memory/pool.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/fault/code.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/fault/compatible.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/fault/handling.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/exception/deviant.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/exception/network.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/exception/protocol.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/exception/security.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/coroutine/registry.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/foundation/rate/counter.hpp
)
