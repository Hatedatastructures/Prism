prism_add_test(WsCodec.cpp)
prism_add_test(WsSchemeDeep.cpp)

prism_add_test(WsE2E.cpp)
prism_add_test(WsConnSession.cpp)
target_link_libraries(WsConnSession PRIVATE vmtest_common)

