target_sources(PrismStaticLibrary
        PRIVATE
        encrypted.cpp
        pad.cpp
        preview.cpp
        quic/server.cpp
)

target_sources(PrismStaticLibrary
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/net/transport/transmission.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/transport/reliable.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/transport/unreliable.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/transport/encrypted.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/transport/pad.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/transport/preview.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/transport/snapshot.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/transport/adapter/connector.hpp
)
