target_sources(${PROJECT_NAME}_static_library
        PRIVATE
        pipeline/chain.cpp
        pipeline/stages/reality.cpp
        pipeline/stages/shadowtls.cpp
        pipeline/stages/standard.cpp
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/agent.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/config.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/context.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/pipeline/ctxdef.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/pipeline/stage.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/pipeline/chain.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/pipeline/stages/reality.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/pipeline/stages/shadowtls.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/pipeline/stages/standard.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/agent/dispatch/table.hpp

)

add_subdirectory(account)
add_subdirectory(session)
add_subdirectory(front)
add_subdirectory(worker)
add_subdirectory(dispatch)
