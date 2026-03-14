target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        header.cpp
        request.cpp
        response.cpp
        serialization.cpp
        deserialization.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/http/header.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/http/request.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/http/response.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/http/serialization.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/http/deserialization.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/protocol/http/constants.hpp
)
