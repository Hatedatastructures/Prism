target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        parser.cpp
        relay.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/http/parser.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/http/relay.hpp
)
