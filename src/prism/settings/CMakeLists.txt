target_sources(${PROJECT_NAME}_static_library
        PRIVATE
            validator.cpp
)

target_sources(${PROJECT_NAME}_static_library
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/settings/settings.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/settings/validator.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/settings/loader/load.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/settings/transformer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/settings/transformer/json.hpp
)
