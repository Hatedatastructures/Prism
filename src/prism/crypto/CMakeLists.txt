target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        blake3.cpp
        aead.cpp
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
)
