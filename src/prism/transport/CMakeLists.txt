target_sources(${PROJECT_NAME}_static_library
    PRIVATE
        encrypted.cpp
        preview.cpp
)

target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers
    BASE_DIRS ${CMAKE_SOURCE_DIR}/include
    FILES
        ${CMAKE_SOURCE_DIR}/include/prism/transport.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/transport/transmission.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/transport/reliable.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/transport/unreliable.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/transport/encrypted.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/transport/preview.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/transport/snapshot.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/transport/adapter/connector.hpp
)
