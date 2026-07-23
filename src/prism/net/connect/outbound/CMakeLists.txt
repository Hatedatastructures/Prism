target_sources(${PROJECT_NAME}_static_library
        PRIVATE
            dial.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/outbound/proxy.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/outbound/direct.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connect/outbound/dial.hpp
)
