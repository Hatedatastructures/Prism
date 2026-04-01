target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        analysis.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/protocol.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/analysis.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/http.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/probe.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/socks5.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/trojan.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/common/form.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/socks5/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/socks5/constants.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/socks5/message.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/socks5/stream.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/socks5/wire.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/trojan/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/trojan/constants.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/trojan/message.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/trojan/stream.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/trojan/wire.hpp
)

add_subdirectory(http)
