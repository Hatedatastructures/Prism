target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        pool/pool.cpp
        pool/health.cpp
        dial/router.cpp
        dial/dial.cpp
        dial/racer.cpp
        route/table.cpp
        tunnel/tunnel.cpp
        tunnel/tunnel_relay.cpp
        tunnel/forward/basic.cpp
        tunnel/forward_relay.cpp
        tunnel/forward/pipeline.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/pool/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/pool/health.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/pool/pool.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/dial/router.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/dial/racer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/dial/dial.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/route/table.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/tunnel/tunnel.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/tunnel/tunnel_relay.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/tunnel/forward/basic.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/tunnel/forward_relay.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/tunnel/forward/pipeline.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/util.hpp
)
