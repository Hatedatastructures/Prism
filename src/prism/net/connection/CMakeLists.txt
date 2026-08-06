target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        dialer/dialer.cpp
        dialer/racer.cpp
        route/table.cpp
        tunnel/tunnel.cpp
        tunnel/tunnel_relay.cpp
        tunnel/forward/basic.cpp
        tunnel/forward_relay.cpp
        tunnel/forward/pipeline.cpp
)

add_subdirectory(outbound)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/dialer/racer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/dialer/dialer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/route/table.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/tunnel/tunnel.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/tunnel/tunnel_relay.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/tunnel/forward/basic.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/tunnel/forward_relay.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/tunnel/forward/pipeline.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/util.hpp
)
