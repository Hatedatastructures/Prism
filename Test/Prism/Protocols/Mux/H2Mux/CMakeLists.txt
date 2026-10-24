AddPrismTest(H2MuxFrameError.cpp)
target_link_libraries(H2MuxFrameError PRIVATE PrismProtocolMux PrismTestSupport)

AddPrismTest(H2MuxFrameTest.cpp)
target_link_libraries(H2MuxFrameTest PRIVATE PrismProtocolMux)
AddPrismTest(H2MuxReadTerminalTest.cpp)
target_link_libraries(H2MuxReadTerminalTest PRIVATE PrismFoundation PrismTransport
    PrismProtocolHttp2 PrismProtocolMux)
AddPrismTest(H2MuxWriteShutdownTest.cpp)
target_link_libraries(H2MuxWriteShutdownTest PRIVATE PrismFoundation PrismTransport
    PrismProtocolHttp2 PrismProtocolMux)
AddPrismTest(H2MuxEngineRetirementTest.cpp)
target_link_libraries(H2MuxEngineRetirementTest PRIVATE PrismFoundation PrismTransport
    PrismRuntime PrismComposition PrismProtocolHttp2)

foreach(_case IN ITEMS H2MuxReadLifetimeTest H2MuxWriteLifetimeTest
        H2MuxRequestAdmissionTest)
    AddPrismTest(${_case}.cpp)
    target_sources(${_case} PRIVATE H2MuxLifetimeSupport.hpp)
    target_link_libraries(${_case} PRIVATE PrismFoundation PrismTransport PrismRuntime
        PrismComposition PrismProtocolHttp2)
endforeach()
