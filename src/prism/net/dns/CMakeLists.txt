target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        upstream.cpp
        resolver.cpp
        detail/format.cpp
        detail/cache.cpp
        detail/rules.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/resolver.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/upstream.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/detail/cache.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/detail/coalescer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/detail/format.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/detail/rules.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/detail/transparent.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/detail/utility.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/net/dns/serialize.hpp
)
