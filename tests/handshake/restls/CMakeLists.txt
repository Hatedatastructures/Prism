AddProductionTest(Restls.cpp)
AddProductionTest(RestlsScript.cpp)
# 以下测试引用了旧的 restls 内部函数（extract_server_random / is_tls13_server_hello /
# decode_restls_payload 等），restls 重写后已删除。待新 API 稳定后重写。
# AddProductionTest(RestlsHandshakePure.cpp)
# AddProductionTest(RestlsHandshakePure2.cpp)
AddProductionTest(RestlsHandshakeParse2.cpp)
# AddProductionTest(RestlsTransportPure.cpp)
# AddProductionTest(RestlsTransportDeep.cpp)
