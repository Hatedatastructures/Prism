target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        primitives.cpp
        protocols.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/pipeline/primitives.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/agent/pipeline/protocols.hpp
)
