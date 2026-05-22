target_sources(${PROJECT_NAME}_static_library
    PRIVATE
        state.cpp
)

target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers
    BASE_DIRS ${CMAKE_SOURCE_DIR}/include
    FILES
        ${CMAKE_SOURCE_DIR}/include/prism/stats/stats.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/stats/snapshot.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/stats/state.hpp
)
