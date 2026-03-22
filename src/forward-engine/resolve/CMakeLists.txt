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
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/coalescer.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/router.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/transparent.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/config.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/packet.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/resolver.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/cache.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/rules.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/resolve/recursor.hpp
)
