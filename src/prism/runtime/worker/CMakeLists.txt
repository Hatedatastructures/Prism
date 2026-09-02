target_sources(PrismStaticLibrary
        PRIVATE
            launch.cpp
            tls.cpp
            worker.cpp
)

target_sources(PrismStaticLibrary
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/worker/launch.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/worker/tls.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/worker/worker.hpp
)
