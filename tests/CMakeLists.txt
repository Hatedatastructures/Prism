function(forward_add_test test_name source_file)
    add_executable(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE ${PROJECT_NAME}_static_library)
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

forward_add_test(headers_test header.cpp)

add_executable(main_test main_test.cpp)
target_compile_options(main_test PRIVATE
        -g1
        -O1
        -fno-keep-inline-dllexport
        -fno-function-sections
        -fno-data-sections
)
target_link_libraries(main_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME main_test COMMAND main_test)

forward_add_test(json_test json_test.cpp)
forward_add_test(request_test request.cpp)
forward_add_test(glaze_test glaze_test.cpp)
forward_add_test(log_test log.cpp)

add_executable(session_test session.cpp)
target_compile_options(session_test PRIVATE
        -g1
        -O1
        -fno-keep-inline-dllexport
)
target_link_libraries(session_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME session_test COMMAND session_test)

forward_add_test(connection_test connection_test.cpp)
forward_add_test(spdlog_test spdlog_test.cpp)

add_executable(socks5_test socks5_test.cpp)
target_compile_options(socks5_test PRIVATE -g1 -Os -fno-keep-inline-dllexport)
target_link_libraries(socks5_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME socks5_test COMMAND socks5_test)

add_executable(trojan_test trojan_test.cpp)
target_compile_options(trojan_test PRIVATE -g1 -Os -fno-keep-inline-dllexport)
target_link_libraries(trojan_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME trojan_test COMMAND trojan_test)

add_executable(trojan_client_test trojan_client_test.cpp)
target_compile_options(trojan_client_test PRIVATE -g1 -Os -fno-keep-inline-dllexport)
target_link_libraries(trojan_client_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME trojan_client_test COMMAND trojan_client_test)

add_executable(transmission_test transmission_test.cpp)
target_compile_options(transmission_test PRIVATE -g1 -Os -fno-keep-inline-dllexport)
target_link_libraries(transmission_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME transmission_test COMMAND transmission_test)

add_executable(integration_test integration_test.cpp)
target_compile_options(integration_test PRIVATE -g1 -Os -fno-keep-inline-dllexport)
target_link_libraries(integration_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME integration_test COMMAND integration_test)

add_executable(regression_test regression_test.cpp)
target_compile_options(regression_test PRIVATE -g1 -Os -fno-keep-inline-dllexport)
target_link_libraries(regression_test PRIVATE ${PROJECT_NAME}_static_library)
add_test(NAME regression_test COMMAND regression_test)

add_subdirectory(concurrency)

if(MINGW)
    foreach(target_name IN ITEMS
            headers_test
            main_test
            json_test
            request_test
            glaze_test
            log_test
            session_test
            connection_test
            spdlog_test
            socks5_test
            trojan_test
            trojan_client_test
            transmission_test
            integration_test
            regression_test
            concurrency_server
            concurrency_client)
        if(TARGET ${target_name})
            target_compile_options(${target_name} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()