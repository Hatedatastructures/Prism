target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        reality/request.cpp
        reality/auth.cpp
        reality/keygen.cpp
        reality/response.cpp
        reality/seal.cpp
        reality/handshake.cpp
        reality/scheme.cpp
        shadowtls/auth.cpp
        shadowtls/handshake.cpp
        shadowtls/scheme.cpp
        native.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/stealth.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/scheme.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/native.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/constants.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/request.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/auth.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/keygen.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/response.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/seal.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/handshake.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/reality/scheme.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/shadowtls/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/shadowtls/constants.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/shadowtls/auth.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/shadowtls/handshake.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/stealth/shadowtls/scheme.hpp
)
