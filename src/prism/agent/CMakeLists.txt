target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/agent.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/context.hpp
)

add_subdirectory(account)
add_subdirectory(session)
add_subdirectory(front)
add_subdirectory(pipeline)
add_subdirectory(worker)
add_subdirectory(dispatch)

