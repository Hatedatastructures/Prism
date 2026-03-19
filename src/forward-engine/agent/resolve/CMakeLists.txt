target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        tcpcache.cpp
        udpcache.cpp
        router.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/resolve/arbiter.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/resolve/coalescer.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/resolve/tcpcache.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/resolve/udpcache.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/resolve/router.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/resolve/transparent.hpp
)
