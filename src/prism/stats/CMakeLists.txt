target_sources(${PROJECT_NAME}_static_library
    PRIVATE
        runtime.cpp
        traffic.cpp
)

target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers
    BASE_DIRS ${CMAKE_SOURCE_DIR}/include
    FILES
        ${CMAKE_SOURCE_DIR}/include/prism/stats/stats.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/stats/snapshot.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/stats/counter.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/stats/gauge.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/stats/runtime.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/stats/traffic.hpp
        ${CMAKE_SOURCE_DIR}/include/prism/stats/account.hpp
)
