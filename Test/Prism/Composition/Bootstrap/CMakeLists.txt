# Composition 启动装配测试。
AddPrismTest(ProfileBootstrapTest.cpp)
target_link_libraries(ProfileBootstrapTest PRIVATE
    PrismComposition PrismRuntime PrismFoundation PrismTestSupport)
