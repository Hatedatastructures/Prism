target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/exception.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/fault.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/memory.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transformer.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/exception/deviant.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/exception/network.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/exception/protocol.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/exception/security.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/loader/load.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/config.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/fault/code.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/fault/compatible.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/fault/handling.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/memory/container.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/memory/pointer.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/memory/pool.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transformer/json.hpp
)

add_subdirectory(channel)
add_subdirectory(protocol)
add_subdirectory(trace)
add_subdirectory(resolve)
add_subdirectory(agent)
add_subdirectory(crypto)
add_subdirectory(multiplex)
