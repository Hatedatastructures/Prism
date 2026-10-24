# 网络压力测试。
AddPrismTest(NetworkingStressTest.cpp)
target_link_libraries(NetworkingStressTest PRIVATE
    PrismTransport PrismNet PrismTestSupport)
