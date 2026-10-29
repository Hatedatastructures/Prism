# native 子模块
AddPrismTest(Connection/ConnTest.cpp NativeConnTest)
target_link_libraries(NativeConnTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolNative PrismProtocolEch OpenSSL::SSL OpenSSL::Crypto)
