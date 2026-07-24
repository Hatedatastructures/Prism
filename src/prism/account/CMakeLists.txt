target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        directory.cpp

        stats/runtime.cpp
        stats/traffic.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/account/account.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/entry.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/directory.hpp

            ${PROJECT_SOURCE_DIR}/include/prism/account/stats/stats.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/stats/record.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/stats/counter.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/stats/gauge.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/stats/memory.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/stats/runtime.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/stats/snapshot.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/account/stats/traffic.hpp
)
