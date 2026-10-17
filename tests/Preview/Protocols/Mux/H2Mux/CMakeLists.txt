AddPreviewTest(H2MuxFrameError.cpp)
target_link_libraries(H2MuxFrameError PRIVATE PreviewProtocolMux PreviewTestSupport)
AddPreviewTest(H2MuxEngineRetirementTest.cpp)
target_link_libraries(H2MuxEngineRetirementTest PRIVATE PreviewFoundation PreviewTransport
    PreviewRuntime PreviewComposition PreviewProtocolHttp2)

AddPreviewTest(MuxH2RootOwnerTest.cpp)
target_link_libraries(MuxH2RootOwnerTest PRIVATE PreviewProtocolTrojan PreviewProtocolMux)
foreach(_case IN ITEMS H2MuxStreamReadLifetimeTest H2MuxStreamWriteLifetimeTest)
    AddPreviewTest(${_case}.cpp)
    target_sources(${_case} PRIVATE H2MuxStreamLifetimeTestSupport.hpp)
    target_link_libraries(${_case} PRIVATE PreviewFoundation PreviewTransport PreviewRuntime
        PreviewComposition PreviewProtocolHttp2)
endforeach()
