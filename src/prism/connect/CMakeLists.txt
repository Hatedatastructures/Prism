target_sources(${PROJECT_NAME}_static_library
    PRIVATE
        pool/pool.cpp
        pool/health.cpp
        dial/router.cpp
        dial/dial.cpp
        dial/racer.cpp
        tunnel/tunnel.cpp
        tunnel/forward.cpp
)

target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers
    BASE_DIRS ${CMAKE_SOURCE_DIR}/include
    FILES
        ${CMAKE_SOURCE_DIR}/include/prism/connect.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/pool/config.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/pool/health.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/pool/pool.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/dial/router.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/dial/racer.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/dial/dial.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/tunnel/tunnel.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/tunnel/forward.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/connect/util.hpp
)
