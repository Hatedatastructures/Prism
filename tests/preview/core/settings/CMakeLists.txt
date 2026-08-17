# settings 子模块测试
prism_add_test(SettingsApiTest.cpp)
target_link_libraries(SettingsApiTest PRIVATE vmtest_common)
