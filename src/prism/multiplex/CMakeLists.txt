target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        core.cpp
        duct.cpp
        parcel.cpp
        bootstrap.cpp
        smux/frame.cpp
        smux/craft.cpp
        yamux/frame.cpp
        yamux/craft.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/core.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/duct.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/parcel.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/bootstrap.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/smux/frame.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/smux/craft.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/smux/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/yamux/frame.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/yamux/craft.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/multiplex/yamux/config.hpp
)
