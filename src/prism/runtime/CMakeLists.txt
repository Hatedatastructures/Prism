target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/runtime.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/serialize.hpp
)

add_subdirectory(session)
add_subdirectory(front)
add_subdirectory(worker)
