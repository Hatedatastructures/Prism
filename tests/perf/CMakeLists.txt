# 性能测量工具：连接运行中的 Prism 代理，不注册 ctest（依赖外部进程）
add_executable(ProtocolPerf ProtocolPerf.cpp)
target_compile_options(ProtocolPerf PRIVATE -g1 -Os)
target_link_libraries(ProtocolPerf PRIVATE ${PROJECT_NAME}_static_library)
target_include_directories(ProtocolPerf BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
    ${CMAKE_SOURCE_DIR}/src)
if(MINGW)
    target_compile_options(ProtocolPerf PRIVATE -Wa,-mbig-obj -fno-keep-inline-dllexport)
    set_target_properties(ProtocolPerf PROPERTIES
        ENABLE_EXPORTS OFF
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
endif()

# 多线程黑洞后端（性能测试用，不注册 ctest）
add_executable(BlackholeServer BlackholeServer.cpp)
target_compile_options(BlackholeServer PRIVATE -g1 -Os)
target_link_libraries(BlackholeServer PRIVATE ${PROJECT_NAME}_static_library)
target_include_directories(BlackholeServer BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/src)
set_target_properties(BlackholeServer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")

# 异步 HTTP 文件服务（性能测试后端）
add_executable(FileServer FileServer.cpp)
target_compile_options(FileServer PRIVATE -g1 -Os)
target_link_libraries(FileServer PRIVATE ${PROJECT_NAME}_static_library)
target_include_directories(FileServer BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/src)
set_target_properties(FileServer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")

# 加密并行性测试
add_executable(EncryptParallel EncryptParallel.cpp)
target_compile_options(EncryptParallel PRIVATE -g1 -Os)
target_link_libraries(EncryptParallel PRIVATE ${PROJECT_NAME}_static_library)
target_include_directories(EncryptParallel BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/src)
set_target_properties(EncryptParallel PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
