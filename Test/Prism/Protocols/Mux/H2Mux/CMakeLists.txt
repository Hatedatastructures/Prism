AddPrismTest(FrameError.cpp H2MuxFrameError)
target_link_libraries(H2MuxFrameError PRIVATE PrismProtocolMux PrismTestSupport)

AddPrismTest(FrameTest.cpp H2MuxFrameTest)
target_link_libraries(H2MuxFrameTest PRIVATE PrismProtocolMux)
AddPrismTest(ReadTerminalTest.cpp H2MuxReadTerminalTest)
target_link_libraries(H2MuxReadTerminalTest PRIVATE PrismFoundation PrismTransport
    PrismProtocolHttp2 PrismProtocolMux)
AddPrismTest(WriteShutdownTest.cpp H2MuxWriteShutdownTest)
target_include_directories(H2MuxWriteShutdownTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(H2MuxWriteShutdownTest PRIVATE PrismFoundation PrismTransport
    PrismProtocolHttp2 PrismProtocolMux)
AddPrismTest(EngineRetirementTest.cpp H2MuxEngineRetirementTest)
target_link_libraries(H2MuxEngineRetirementTest PRIVATE PrismFoundation PrismTransport
    PrismRuntime PrismComposition PrismProtocolHttp2)

foreach(_case IN ITEMS H2MuxReadLifetimeTest H2MuxWriteLifetimeTest
        H2MuxRequestAdmissionTest)
    string(REGEX REPLACE "^H2Mux" "" _source_stem ${_case})
    AddPrismTest(${_source_stem}.cpp ${_case})
    target_sources(${_case} PRIVATE LifetimeSupport.hpp)
    target_link_libraries(${_case} PRIVATE PrismFoundation PrismTransport PrismRuntime
        PrismComposition PrismProtocolHttp2)
endforeach()
target_include_directories(H2MuxReadLifetimeTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
