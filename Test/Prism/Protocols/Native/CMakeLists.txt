# native 子模块
AddPrismTest(Connection/NativeConnTest.cpp)
target_link_libraries(NativeConnTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolNative PrismProtocolEch OpenSSL::SSL OpenSSL::Crypto)
