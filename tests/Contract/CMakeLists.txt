# psm 与 Preview 的公共协议契约测试
AddContractTest(ProtocolContractTest.cpp)
target_link_libraries(ProtocolContractTest PRIVATE
    PreviewProtocolSocks5
    PreviewProtocolVless
    PreviewProtocolTrojan
    PreviewProtocolVmess
    PreviewProtocolShadowsocks2022)

AddContractTest(TransportContractTest.cpp)
target_link_libraries(TransportContractTest PRIVATE PreviewTransport PreviewNet ContractTestSupport )
