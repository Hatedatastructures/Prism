add_library(${PROJECT_NAME}_static_library STATIC)

target_include_directories(${PROJECT_NAME}_static_library
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/include/prism
        ${boost_include_dir}
        ${Boost_INCLUDE_DIRS}
        ${nghttp3_SOURCE_DIR}/lib/includes
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${ngtcp2_SOURCE_DIR}/lib/includes
        ${ngtcp2_SOURCE_DIR}/crypto/includes
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
        ngtcp2_static
        ngtcp2_crypto_boringssl_static
        nghttp3_static
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME}_static_library PUBLIC ws2_32 mswsock crypt32 dbghelp)
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

# 同步默认配置到 exe 同目录（Prism 默认加载 exe 同目录 configuration.json，
# 避免旧配置缺失 QUIC/Hysteria2/TUIC 导致网关不启动）
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/configuration.json
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/configuration.json
)

if(MINGW)
    # GCC 16.1.0 静态链接 libstdc++ 有未解析符号 (wctob/btowc)，使用动态链接
    # 运行时需要 ucrt64/bin 在 PATH 中
    target_link_options(${PROJECT_NAME} PRIVATE
            -static-libgcc
    )
    # CMake 默认为 MinGW executable 加 --out-implib 生成导入库，与 --gc-sections
    # 组合在某些 MinGW 版本上触发 "ld returned 5 exit status" 错误。
    # 重写 link 命令，移除 --out-implib 与 --major/minor-image-version。
    set(CMAKE_CXX_LINK_EXECUTABLE
        "<CMAKE_CXX_COMPILER> <FLAGS> <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${PROJECT_NAME} PRIVATE
            -g1
            -Os
    )
endif()

if(MINGW)
    target_compile_options(${PROJECT_NAME} PRIVATE -fno-keep-inline-dllexport)
endif()

target_link_libraries(${PROJECT_NAME}
        PRIVATE
        ${PROJECT_NAME}_static_library
)

# boost 1.89 header-only 的 wrapexcept thunk 被 --gc-sections 裁剪，禁用裁剪
# （--image-base 为 PE/COFF 专属选项，Linux ELF ld 无法识别，仅 WIN32 传入）
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(${PROJECT_NAME} PRIVATE -Wl,--no-gc-sections)
    if(WIN32)
        target_link_options(${PROJECT_NAME} PRIVATE -Wl,--image-base,0x140000000)
    endif()
endif()

# Prism 可执行文件不参与覆盖率（GoCompat 需要干净的链接；--coverage 破坏 boost thunk）
# Prism 链接 coverage 库时需与库一致（避免 relocation 溢出）；wrapexcept thunk 由专用 TU 提供
# main.cpp 单独移除 coverage 插桩（避免 .xdata relocation 溢出）；库仍插桩
if(PRISM_ENABLE_COVERAGE)
    set_source_files_properties(main.cpp PROPERTIES COMPILE_OPTIONS "-fno-profile-arcs;-fno-test-coverage")
endif()