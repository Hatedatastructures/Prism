add_executable(ConcurrencyServer
    server.cpp
    server.hpp
    conversation.hpp
    handler.hpp
)

target_include_directories(ConcurrencyServer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(ConcurrencyServer PRIVATE
    ${PROJECT_NAME}_static_library
    Boost::system
    glaze::glaze
    spdlog::spdlog
    ws2_32
    crypt32
    mswsock
)

if(MSVC)
    target_compile_options(ConcurrencyServer PRIVATE /W4 /O2 /DNDEBUG)
else()
    target_compile_options(ConcurrencyServer PRIVATE -Wall -Wextra -O2)
    target_compile_definitions(ConcurrencyServer PRIVATE NDEBUG)
endif()

add_executable(ConcurrencyClient client.cpp)

target_include_directories(ConcurrencyClient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(ConcurrencyClient PRIVATE
    ${PROJECT_NAME}_static_library
    Boost::system
    glaze::glaze
    spdlog::spdlog
    ws2_32
    crypt32
    mswsock
)

if(MSVC)
    target_compile_options(ConcurrencyClient PRIVATE /W4 /O2 /DNDEBUG)
else()
    target_compile_options(ConcurrencyClient PRIVATE -Wall -Wextra -O2)
    target_compile_definitions(ConcurrencyClient PRIVATE NDEBUG)
endif()
