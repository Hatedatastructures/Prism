target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        balancer.cpp
        listener.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/agent/front/balancer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/front/listener.hpp
)
