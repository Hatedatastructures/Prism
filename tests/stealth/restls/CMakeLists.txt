prism_add_test(Restls.cpp)
prism_add_test(RestlsScript.cpp)
# 以下测试引用了旧的 restls 内部函数（extract_server_random / is_tls13_server_hello /
# decode_restls_payload 等），restls 重写后已删除。待新 API 稳定后重写。
# prism_add_test(RestlsHandshakePure.cpp)
# prism_add_test(RestlsHandshakePure2.cpp)
prism_add_test(RestlsHandshakeParse2.cpp)
# prism_add_test(RestlsTransportPure.cpp)
# prism_add_test(RestlsTransportDeep.cpp)
