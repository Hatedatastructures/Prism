target_sources(${PROJECT_NAME}_static_library
    PRIVATE
        directory.cpp
)

target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers
    BASE_DIRS ${CMAKE_SOURCE_DIR}/include
    FILES
        ${CMAKE_SOURCE_DIR}/include/prism/account.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/account/entry.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/account/directory.hpp
)
