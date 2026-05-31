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
        blake3_c
        nghttp2_static
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME}_static_library PUBLIC ws2_32 mswsock crypt32)
endif()

target_compile_definitions(${PROJECT_NAME}_static_library
        PUBLIC
        BOOST_ASIO_HEADER_ONLY
        BOOST_ASIO_USE_OPENSSL
        BOOST_ASIO_DISABLE_VISIBILITY       # : 解决 use_awaitable 重复符号问题
#        BOOST_ASIO_ENABLE_HANDLER_TRACKING  # : 启用处理程序跟踪
)

if(WIN32)
    target_compile_definitions(${PROJECT_NAME}_static_library PUBLIC WIN32_LEAN_AND_MEAN)
endif()

add_subdirectory(prism)


add_executable(${PROJECT_NAME}
        main.cpp
)

set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "Prism")

if(MINGW)
    # GCC 16.1.0 静态链接 libstdc++ 有未解析符号 (wctob/btowc)，使用动态链接
    # 运行时需要 ucrt64/bin 在 PATH 中
    target_link_options(${PROJECT_NAME} PRIVATE
            -static-libgcc
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${PROJECT_NAME} PRIVATE
            -g1
            -O1
    )
endif()

if(MINGW)
    target_compile_options(${PROJECT_NAME} PRIVATE -fno-keep-inline-dllexport)
endif()

target_link_libraries(${PROJECT_NAME}
        PRIVATE
        ${PROJECT_NAME}_static_library
)
