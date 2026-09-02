target_sources(PrismStaticLibrary
        PRIVATE
            dial.cpp
)

target_sources(PrismStaticLibrary
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/outbound/direct.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/connection/outbound/dial.hpp
)
