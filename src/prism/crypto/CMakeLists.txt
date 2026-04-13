target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        blake3.cpp
        aead.cpp
        block.cpp
        x25519.cpp
        hkdf.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/crypto/sha224.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/crypto/base64.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/crypto/blake3.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/crypto/aead.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/crypto/block.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/crypto/x25519.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/crypto/hkdf.hpp
)
