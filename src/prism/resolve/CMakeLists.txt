target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        router.cpp
        dns/upstream.cpp
        dns/resolver.cpp
        dns/detail/format.cpp
        dns/detail/cache.cpp
        dns/detail/rules.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/dns.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/upstream.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/detail/cache.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/detail/coalescer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/detail/format.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/detail/rules.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/detail/transparent.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/dns/detail/utility.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/router.hpp
)
