# ech 子模块
AddPrismTest(EchNgxTest.cpp)
target_include_directories(EchNgxTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(EchNgxTest PRIVATE PrismProtocolEch OpenSSL::SSL OpenSSL::Crypto)
