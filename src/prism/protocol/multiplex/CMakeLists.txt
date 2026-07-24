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
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/core.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/duct.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/parcel.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/bootstrap.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/h2mux/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/h2mux/craft.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/smux/frame.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/smux/craft.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/smux/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/yamux/frame.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/yamux/craft.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/protocol/multiplex/yamux/config.hpp
)
