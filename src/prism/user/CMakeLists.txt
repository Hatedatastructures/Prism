target_sources(PrismStaticLibrary
        PRIVATE
        directory.cpp

        stats/runtime.cpp
        stats/traffic.cpp
)

target_sources(PrismStaticLibrary
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/user/user.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/entry.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/directory.hpp

            ${PROJECT_SOURCE_DIR}/include/prism/user/stats/stats.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/stats/record.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/stats/counter.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/stats/gauge.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/stats/memory.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/stats/runtime.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/stats/snapshot.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/user/stats/traffic.hpp
)
