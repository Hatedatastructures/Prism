target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/core/core.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/memory/container.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/memory/pool.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/fault/code.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/fault/compatible.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/fault/handling.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/exception/deviant.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/exception/network.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/exception/protocol.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/core/exception/security.hpp
)
