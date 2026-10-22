AddPrismTest(Codec/MuxCodecTest.cpp)
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
    AddPrismTest(Mux/MuxRealRootMatrix.cpp)
    target_link_libraries(MuxRealRootMatrix PRIVATE
        PrismFoundation PrismAccount PrismIoContracts PrismIngressContract PrismLifecycle
        PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
        PrismProtocolHttp2 PrismProtocolMux PrismProtocolTrojan PrismRuntime PrismTestSupport)
    AddPrismTest(Mux/MuxRealRootLifecycleTest.cpp)
    target_link_libraries(MuxRealRootLifecycleTest PRIVATE
        PrismFoundation PrismAccount PrismIoContracts PrismIngressContract PrismLifecycle
        PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
        PrismProtocolHttp2 PrismProtocolMux PrismProtocolTrojan PrismRuntime PrismTestSupport)
    foreach(_case IN ITEMS MuxPerf MuxRealRootMatrix MuxRealRootLifecycleTest)
target_sources(${_case} PRIVATE Performance/MuxPerfAllocation.cpp Performance/MuxPerfAllocation.hpp)
        target_sources(${_case} PRIVATE
            Mux/MuxRealRootFixture.hpp
            Mux/MuxRealRootMeasurement.hpp
            Mux/MuxAcceptSupport.hpp
            Mux/MuxRealRootWorkload.hpp
            Mux/MuxRealRootProcessMetrics.hpp
            Mux/MuxRealRootMatrixControl.hpp)
    endforeach()
endif()

AddPrismTest(Mux/MuxSessionTest.cpp)
target_sources(MuxSessionTest PRIVATE Mux/MuxSessionTestSupport.hpp)
target_link_libraries(MuxSessionTest PRIVATE
    PrismTransport PrismProtocolMux PrismLifecycle PrismTestSupport)
target_compile_options(MuxSessionTest PRIVATE -O0 -fno-inline)

AddPrismTest(Mux/MuxReadCompletionTest.cpp)
target_include_directories(MuxReadCompletionTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(MuxReadCompletionTest PRIVATE PrismFoundation PrismTransport
    PrismIoContracts PrismNetworkModel PrismNet PrismProtocolHttp2 PrismProtocolMux)

AddPrismTest(Mux/MuxStreamCancellationTest.cpp)
target_sources(MuxStreamCancellationTest PRIVATE Mux/MuxCancelExecutorTest.cpp)
target_link_libraries(MuxStreamCancellationTest PRIVATE
    PrismFoundation PrismLifecycle PrismProtocolMux PrismTransport)

AddPrismTest(Mux/MuxTeardownCauseTest.cpp)
target_link_libraries(MuxTeardownCauseTest PRIVATE PrismFoundation PrismTransport
    PrismIoContracts PrismIngressContract PrismProtocolMux)

AddPrismTest(Codec/MuxSessionDeep2.cpp)
target_link_libraries(MuxSessionDeep2 PRIVATE
    PrismTransport PrismProtocolMux PrismLifecycle PrismTestSupport)
target_compile_options(MuxSessionDeep2 PRIVATE -O0 -fno-inline)

AddPrismTest(Codec/MuxSessionDeep.cpp)
target_link_libraries(MuxSessionDeep PRIVATE PrismTransport PrismProtocolMux PrismTestSupport)
target_compile_options(MuxSessionDeep PRIVATE -O0 -fno-inline)

AddPrismTest(Mux/MuxWriteContract.cpp)
target_sources(MuxWriteContract PRIVATE Mux/MuxWriteContractLifecycle.cpp)
target_link_libraries(MuxWriteContract PRIVATE PrismFoundation PrismTransport PrismProtocolMux PrismTestSupport)

AddPrismTest(Mux/MuxSingWriteProgressTest.cpp)
target_link_libraries(MuxSingWriteProgressTest PRIVATE
    PrismFoundation PrismIoContracts PrismNetworkModel PrismTransport PrismProtocolMux)

AddPrismTest(Mux/MuxOwnershipAuditTest.cpp)
target_sources(MuxOwnershipAuditTest PRIVATE Mux/MuxSessionTestSupport.hpp)
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

AddPrismTest(Mux/MuxRootFinishTest.cpp)
target_sources(MuxRootFinishTest PRIVATE Mux/MuxRootCloseTestSupport.hpp)
target_link_libraries(MuxRootFinishTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolMux)
AddPrismTest(Mux/MuxResetFailureTest.cpp)
target_include_directories(MuxResetFailureTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(MuxResetFailureTest PRIVATE
    PrismFoundation PrismLifecycle PrismIngressContract PrismProtocolMux)
AddPrismTest(Mux/MuxRootCloseTest.cpp)
target_sources(MuxRootCloseTest PRIVATE Mux/MuxRootCloseTestSupport.hpp)
target_link_libraries(MuxRootCloseTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolTrojan PrismProtocolMux
    PrismProtocolHttp2 PrismTestSupport)
AddPrismTest(Mux/MuxServiceTest.cpp)
target_sources(MuxServiceTest PRIVATE
    Mux/MuxBootstrapPriorityTest.cpp
    Mux/MuxRootCloseTestSupport.hpp)
target_link_libraries(MuxServiceTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismStreamContract PrismProtocolsCommon
    PrismLifecycle PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolTrojan PrismProtocolMux PrismRuntime)
