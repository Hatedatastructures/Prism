target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/instance.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/instance/config.hpp
)

add_subdirectory(session)
add_subdirectory(front)
add_subdirectory(worker)
