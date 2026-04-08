target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/exception.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/fault.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/memory.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/transformer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/exception/deviant.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/exception/network.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/exception/protocol.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/exception/security.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/loader/load.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/fault/code.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/fault/compatible.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/fault/handling.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/memory/container.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/memory/pointer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/memory/pool.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/transformer/json.hpp
)

add_subdirectory(channel)
add_subdirectory(protocol)
add_subdirectory(trace)
add_subdirectory(resolve)
add_subdirectory(pipeline)
add_subdirectory(agent)
add_subdirectory(crypto)
add_subdirectory(multiplex)
