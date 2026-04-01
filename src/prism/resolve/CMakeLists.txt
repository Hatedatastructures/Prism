target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        router.cpp
        packet.cpp
        resolver.cpp
        cache.cpp
        rules.cpp
        recursor.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/coalescer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/router.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/transparent.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/packet.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/resolver.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/cache.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/rules.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/resolve/recursor.hpp
)
