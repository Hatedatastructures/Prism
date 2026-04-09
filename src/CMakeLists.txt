add_library(${PROJECT_NAME}_static_library STATIC)

target_include_directories(${PROJECT_NAME}_static_library
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/include/prism
        ${boost_include_dir}
        ${Boost_INCLUDE_DIRS}
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}_static_library
        PUBLIC
        spdlog::spdlog
        glaze::glaze
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
        ws2_32
        mswsock
        crypt32
)

target_compile_definitions(${PROJECT_NAME}_static_library
        PUBLIC
        BOOST_ASIO_HEADER_ONLY
        BOOST_ASIO_USE_OPENSSL
        BOOST_ASIO_DISABLE_VISIBILITY       # : 解决 use_awaitable 重复符号问题
#        BOOST_ASIO_ENABLE_HANDLER_TRACKING  # : 启用处理程序跟踪
        WIN32_LEAN_AND_MEAN
)

add_subdirectory(prism)


add_executable(${PROJECT_NAME}
        main.cpp
)


target_link_options(${PROJECT_NAME} PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
)

target_compile_options(${PROJECT_NAME} PRIVATE
        -g1
        -O1
        -fno-keep-inline-dllexport
)

target_link_libraries(${PROJECT_NAME}
        PRIVATE
        ${PROJECT_NAME}_static_library
)
