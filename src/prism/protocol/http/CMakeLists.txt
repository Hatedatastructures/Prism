target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        codec/parser.cpp
        handler/conn.cpp
        handler/handler.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/http/codec/parser.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/http/handler/conn.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/http/handler/handler.hpp
)
