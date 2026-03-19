target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        analysis.cpp
        frame.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/analysis.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/frame.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/http.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/probe.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/socks5.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/trojan.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/common/form.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/socks5/config.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/socks5/constants.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/socks5/message.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/socks5/stream.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/socks5/wire.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/trojan/config.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/trojan/constants.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/trojan/message.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/trojan/stream.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/trojan/wire.hpp
)

add_subdirectory(http)
