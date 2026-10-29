AddPrismTest(Codec/CodecTest.cpp MuxCodecTest)
target_link_libraries(MuxCodecTest PRIVATE PrismProtocolMux PrismTestSupport)
AddPrismTest(Codec/AnytlsWireTest.cpp)
target_include_directories(AnytlsWireTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(AnytlsWireTest PRIVATE PrismProtocolMux)

if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/MuxPerf.cpp)
 target_link_libraries(MuxPerf PRIVATE PrismFoundation PrismAccount PrismIoContracts
     PrismIngressContract PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022
     PrismProtocolSocks5 PrismProtocolMux PrismProtocolTrojan PrismProtocolHttp2
     PrismRuntime PrismTestSupport)
    AddPrismTest(Mux/RealRootMatrix.cpp MuxRealRootMatrix)
    target_link_libraries(MuxRealRootMatrix PRIVATE
        PrismFoundation PrismAccount PrismIoContracts PrismIngressContract PrismLifecycle
        PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
        PrismProtocolHttp2 PrismProtocolMux PrismProtocolTrojan PrismRuntime PrismTestSupport)
    AddPrismTest(Mux/RealRootLifecycleTest.cpp MuxRealRootLifecycleTest)
    target_link_libraries(MuxRealRootLifecycleTest PRIVATE
        PrismFoundation PrismAccount PrismIoContracts PrismIngressContract PrismLifecycle
        PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
        PrismProtocolHttp2 PrismProtocolMux PrismProtocolTrojan PrismRuntime PrismTestSupport)
    foreach(_case IN ITEMS MuxPerf MuxRealRootMatrix MuxRealRootLifecycleTest)
target_sources(${_case} PRIVATE Performance/PerfAllocation.cpp Performance/PerfAllocation.hpp)
        target_sources(${_case} PRIVATE
            Mux/RealRootFixture.hpp
            Mux/RealRootMeasurement.hpp
            Mux/AcceptSupport.hpp
            Mux/RealRootWorkload.hpp
            Mux/RootMetrics.hpp
            Mux/RealRootMatrixControl.hpp)
    endforeach()
endif()

AddPrismTest(Mux/SessionTest.cpp MuxSessionTest)
target_sources(MuxSessionTest PRIVATE Mux/SessionTestSupport.hpp)
target_link_libraries(MuxSessionTest PRIVATE
    PrismTransport PrismProtocolMux PrismLifecycle PrismTestSupport)
target_compile_options(MuxSessionTest PRIVATE -O0 -fno-inline)

AddPrismTest(Mux/ReadCompletionTest.cpp MuxReadCompletionTest)
target_include_directories(MuxReadCompletionTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(MuxReadCompletionTest PRIVATE PrismFoundation PrismTransport
    PrismIoContracts PrismNetworkModel PrismNet PrismProtocolHttp2 PrismProtocolMux)

AddPrismTest(Mux/StreamCancelTest.cpp MuxStreamCancellationTest)
target_sources(MuxStreamCancellationTest PRIVATE Mux/CancelExecutorTest.cpp)
target_link_libraries(MuxStreamCancellationTest PRIVATE
    PrismFoundation PrismLifecycle PrismProtocolMux PrismTransport)

AddPrismTest(Mux/TeardownCauseTest.cpp MuxTeardownCauseTest)
target_link_libraries(MuxTeardownCauseTest PRIVATE PrismFoundation PrismTransport
    PrismIoContracts PrismIngressContract PrismProtocolMux)

AddPrismTest(Codec/SessionDeep2.cpp MuxSessionDeep2)
target_link_libraries(MuxSessionDeep2 PRIVATE
    PrismTransport PrismProtocolMux PrismLifecycle PrismTestSupport)
target_compile_options(MuxSessionDeep2 PRIVATE -O0 -fno-inline)

AddPrismTest(Codec/SessionDeep.cpp MuxSessionDeep)
target_link_libraries(MuxSessionDeep PRIVATE PrismTransport PrismProtocolMux PrismTestSupport)
target_compile_options(MuxSessionDeep PRIVATE -O0 -fno-inline)

AddPrismTest(Mux/WriteContract.cpp MuxWriteContract)
target_sources(MuxWriteContract PRIVATE Mux/WriteLifecycle.cpp)
target_link_libraries(MuxWriteContract PRIVATE PrismFoundation PrismTransport PrismProtocolMux PrismTestSupport)

AddPrismTest(Mux/WriteProgressTest.cpp MuxSingWriteProgressTest)
target_link_libraries(MuxSingWriteProgressTest PRIVATE
    PrismFoundation PrismIoContracts PrismNetworkModel PrismTransport PrismProtocolMux)

AddPrismTest(Mux/OwnershipAuditTest.cpp MuxOwnershipAuditTest)
target_sources(MuxOwnershipAuditTest PRIVATE Mux/SessionTestSupport.hpp)
target_link_libraries(MuxOwnershipAuditTest PRIVATE
    PrismProtocolMux PrismTransport PrismTestSupport)

add_subdirectory(H2Mux)
target_link_libraries(H2MuxEngineRetirementTest PRIVATE PrismProtocolMux)
foreach(_case IN ITEMS H2MuxReadLifetimeTest H2MuxWriteLifetimeTest
        H2MuxRequestAdmissionTest)
    target_link_libraries(${_case} PRIVATE PrismProtocolMux)
endforeach()
add_subdirectory(Smux)
add_subdirectory(Yamux)

AddPrismTest(Mux/RootFinishTest.cpp MuxRootFinishTest)
target_sources(MuxRootFinishTest PRIVATE Mux/RootCloseTestSupport.hpp)
target_link_libraries(MuxRootFinishTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolMux)
AddPrismTest(Mux/ResetFailureTest.cpp MuxResetFailureTest)
target_include_directories(MuxResetFailureTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(MuxResetFailureTest PRIVATE
    PrismFoundation PrismLifecycle PrismIngressContract PrismProtocolMux)
AddPrismTest(Mux/RootCloseTest.cpp MuxRootCloseTest)
target_sources(MuxRootCloseTest PRIVATE Mux/RootCloseTestSupport.hpp)
target_link_libraries(MuxRootCloseTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolTrojan PrismProtocolMux
    PrismProtocolHttp2 PrismTestSupport)
AddPrismTest(Mux/ServiceTest.cpp MuxServiceTest)
target_sources(MuxServiceTest PRIVATE
    Mux/BootstrapPriorityTest.cpp
    Mux/RootCloseTestSupport.hpp)
target_link_libraries(MuxServiceTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismStreamContract PrismProtocolsCommon
    PrismLifecycle PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolTrojan PrismProtocolMux PrismRuntime)
