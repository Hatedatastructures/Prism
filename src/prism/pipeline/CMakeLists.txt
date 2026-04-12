target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        primitives.cpp
        protocols/http.cpp
        protocols/socks5.cpp
        protocols/trojan.cpp
        protocols/vless.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/pipeline/primitives.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/pipeline/protocols/http.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/pipeline/protocols/socks5.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/pipeline/protocols/trojan.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/pipeline/protocols/vless.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/pipeline/protocols.hpp
)
