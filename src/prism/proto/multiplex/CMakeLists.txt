target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        core.cpp
        duct.cpp
        parcel.cpp
        bootstrap.cpp
        h2mux/craft.cpp
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
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/core.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/duct.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/parcel.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/bootstrap.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/h2mux/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/h2mux/craft.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/smux/frame.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/smux/craft.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/smux/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/yamux/frame.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/yamux/craft.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/proto/multiplex/yamux/config.hpp
)
