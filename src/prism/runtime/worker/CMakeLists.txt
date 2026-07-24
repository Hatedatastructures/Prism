target_sources(${PROJECT_NAME}_static_library
        PRIVATE
            launch.cpp
            tls.cpp
            worker.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/worker/launch.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/worker/tls.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/worker/worker.hpp
)
