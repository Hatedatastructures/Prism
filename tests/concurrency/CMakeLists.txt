add_executable(concurrency_server
    server.cpp
    server.hpp
    conversation.hpp
    handler.hpp
)

target_include_directories(concurrency_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    "c:/bin/include"
)

target_link_libraries(concurrency_server PRIVATE
    ${PROJECT_NAME}_static_library
    Boost::system
    glaze::glaze
    spdlog::spdlog
    ws2_32
    crypt32
    mswsock
)

if(MSVC)
    target_compile_options(concurrency_server PRIVATE /W4 /O2 /DNDEBUG)
else()
    target_compile_options(concurrency_server PRIVATE -Wall -Wextra -O2 -DNDEBUG)
endif()

add_executable(concurrency_client client.cpp)

target_include_directories(concurrency_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    "c:/bin/include"
)

target_link_libraries(concurrency_client PRIVATE
    ${PROJECT_NAME}_static_library
    Boost::system
    glaze::glaze
    spdlog::spdlog
    ws2_32
    crypt32
    mswsock
)

if(MSVC)
    target_compile_options(concurrency_client PRIVATE /W4 /O2 /DNDEBUG)
else()
    target_compile_options(concurrency_client PRIVATE -Wall -Wextra -O2 -DNDEBUG)
endif()