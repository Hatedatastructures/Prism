target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/abnormal.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/gist.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/memory.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transformer.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/abnormal/deviant.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/abnormal/network.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/abnormal/protocol.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/abnormal/security.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/adapter/load.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/core/broker.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/core/configuration.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/gist/code.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/gist/compatible.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/gist/handling.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/memory/container.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/memory/pointer.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/memory/pool.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transformer/json.hpp
)

add_subdirectory(channel)
add_subdirectory(protocol)
add_subdirectory(trace)
add_subdirectory(rule)
add_subdirectory(agent)
