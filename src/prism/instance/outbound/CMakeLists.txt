target_sources(${PROJECT_NAME}_static_library
        PRIVATE
            dial.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/instance/outbound/proxy.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/instance/outbound/direct.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/instance/outbound/dial.hpp
)
