target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        core.cpp
        duct.cpp
        parcel.cpp
        smux/frame.cpp
        smux/craft.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/multiplex/config.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/multiplex/core.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/multiplex/duct.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/multiplex/parcel.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/multiplex/smux/frame.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/multiplex/smux/craft.hpp
)