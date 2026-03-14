target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        reverse.cpp
        source.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transport/adaptation.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transport/factory.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transport/form.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transport/reliable.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transport/reverse.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transport/source.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transport/transmission.hpp
            ${PROJECT_SOURCE_DIR}/include/forward-engine/transport/unreliable.hpp
)
