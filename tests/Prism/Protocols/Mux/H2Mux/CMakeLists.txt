AddPrismTest(H2MuxFrameError.cpp)
target_link_libraries(H2MuxFrameError PRIVATE PrismProtocolMux PrismTestSupport)
AddPrismTest(H2MuxEngineRetirementTest.cpp)
target_link_libraries(H2MuxEngineRetirementTest PRIVATE PrismFoundation PrismTransport
    PrismRuntime PrismComposition PrismProtocolHttp2)

AddPrismTest(MuxH2RootOwnerTest.cpp)
target_link_libraries(MuxH2RootOwnerTest PRIVATE PrismProtocolTrojan PrismProtocolMux)
foreach(_case IN ITEMS H2MuxStreamReadLifetimeTest H2MuxStreamWriteLifetimeTest
        H2MuxRequestAdmissionTest)
    AddPrismTest(${_case}.cpp)
    target_sources(${_case} PRIVATE H2MuxStreamLifetimeTestSupport.hpp)
    target_link_libraries(${_case} PRIVATE PrismFoundation PrismTransport PrismRuntime
        PrismComposition PrismProtocolHttp2)
endforeach()
