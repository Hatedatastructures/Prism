AddPrismTest(MuxCodecTest.cpp)
target_link_libraries(MuxCodecTest PRIVATE PrismProtocolMux PrismTestSupport)
AddPrismTest(AnytlsWireTest.cpp)
target_include_directories(AnytlsWireTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(AnytlsWireTest PRIVATE PrismProtocolMux)

if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(MuxPerf.cpp)
 target_link_libraries(MuxPerf PRIVATE PrismFoundation PrismAccount PrismIoContracts
     PrismIngressContract PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022
     PrismProtocolSocks5 PrismProtocolMux PrismProtocolTrojan PrismProtocolHttp2
     PrismRuntime PrismTestSupport)
    AddPrismTest(MuxRealRootMatrix.cpp)
    target_link_libraries(MuxRealRootMatrix PRIVATE
        PrismFoundation PrismAccount PrismIoContracts PrismIngressContract PrismLifecycle
        PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
        PrismProtocolHttp2 PrismProtocolMux PrismProtocolTrojan PrismRuntime PrismTestSupport)
    AddPrismTest(MuxRealRootLifecycleTest.cpp)
    target_link_libraries(MuxRealRootLifecycleTest PRIVATE
        PrismFoundation PrismAccount PrismIoContracts PrismIngressContract PrismLifecycle
        PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
        PrismProtocolHttp2 PrismProtocolMux PrismProtocolTrojan PrismRuntime PrismTestSupport)
    foreach(_case IN ITEMS MuxPerf MuxRealRootMatrix MuxRealRootLifecycleTest)
        target_sources(${_case} PRIVATE MuxPerfAllocation.cpp MuxPerfAllocation.hpp)
        target_sources(${_case} PRIVATE
            MuxRealRootFixture.hpp
            MuxRealRootMeasurement.hpp
            MuxStreamAcceptInputTestSupport.hpp
            MuxRealRootWorkload.hpp
            MuxRealRootProcessMetrics.hpp
            MuxRealRootMatrixControl.hpp)
    endforeach()
endif()

AddPrismTest(MuxSessionTest.cpp)
target_sources(MuxSessionTest PRIVATE MuxSessionTestSupport.hpp)
target_link_libraries(MuxSessionTest PRIVATE
    PrismTransport PrismProtocolMux PrismLifecycle PrismTestSupport)
target_compile_options(MuxSessionTest PRIVATE -O0 -fno-inline)

AddPrismTest(MuxReadCompletionTest.cpp)
target_include_directories(MuxReadCompletionTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(MuxReadCompletionTest PRIVATE PrismFoundation PrismTransport
    PrismIoContracts PrismNetworkModel PrismNet PrismProtocolHttp2 PrismProtocolMux)

AddPrismTest(MuxStreamCancellationTest.cpp)
target_sources(MuxStreamCancellationTest PRIVATE MuxStreamCancellationExecutorTest.cpp)
target_link_libraries(MuxStreamCancellationTest PRIVATE
    PrismFoundation PrismLifecycle PrismProtocolMux PrismTransport)

AddPrismTest(MuxTeardownCauseTest.cpp)
target_link_libraries(MuxTeardownCauseTest PRIVATE PrismFoundation PrismTransport
    PrismIoContracts PrismIngressContract PrismProtocolMux)

AddPrismTest(MuxSessionDeep2.cpp)
target_link_libraries(MuxSessionDeep2 PRIVATE
    PrismTransport PrismProtocolMux PrismLifecycle PrismTestSupport)
target_compile_options(MuxSessionDeep2 PRIVATE -O0 -fno-inline)

AddPrismTest(MuxSessionDeep.cpp)
target_link_libraries(MuxSessionDeep PRIVATE PrismTransport PrismProtocolMux PrismTestSupport)
target_compile_options(MuxSessionDeep PRIVATE -O0 -fno-inline)

AddPrismTest(MuxWriteContract.cpp)
target_sources(MuxWriteContract PRIVATE MuxWriteContractLifecycle.cpp)
target_link_libraries(MuxWriteContract PRIVATE PrismFoundation PrismTransport PrismProtocolMux PrismTestSupport)

AddPrismTest(MuxSingStreamWriteProgressTest.cpp)
target_link_libraries(MuxSingStreamWriteProgressTest PRIVATE
    PrismFoundation PrismIoContracts PrismNetworkModel PrismTransport PrismProtocolMux)

AddPrismTest(MuxSessionOwnershipAuditTest.cpp)
target_sources(MuxSessionOwnershipAuditTest PRIVATE MuxSessionTestSupport.hpp)
target_link_libraries(MuxSessionOwnershipAuditTest PRIVATE
    PrismProtocolMux PrismTransport PrismTestSupport)

add_subdirectory(H2Mux)
target_link_libraries(H2MuxEngineRetirementTest PRIVATE PrismProtocolMux)
foreach(_case IN ITEMS H2MuxStreamReadLifetimeTest H2MuxStreamWriteLifetimeTest
        H2MuxRequestAdmissionTest)
    target_link_libraries(${_case} PRIVATE PrismProtocolMux)
endforeach()
add_subdirectory(Smux)
add_subdirectory(Yamux)

AddPrismTest(MuxRootFinishTest.cpp)
target_sources(MuxRootFinishTest PRIVATE MuxRootCloseTestSupport.hpp)
target_link_libraries(MuxRootFinishTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolMux)
AddPrismTest(MuxRootResetDispatchFailureTest.cpp)
target_include_directories(MuxRootResetDispatchFailureTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(MuxRootResetDispatchFailureTest PRIVATE
    PrismFoundation PrismLifecycle PrismIngressContract PrismProtocolMux)
AddPrismTest(MuxRootCloseTest.cpp)
target_sources(MuxRootCloseTest PRIVATE MuxRootCloseTestSupport.hpp)
target_link_libraries(MuxRootCloseTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolTrojan PrismProtocolMux
    PrismProtocolHttp2 PrismTestSupport)
AddPrismTest(MuxServiceTest.cpp)
target_sources(MuxServiceTest PRIVATE
    MuxBootstrapTerminalPriorityTest.cpp
    MuxRootCloseTestSupport.hpp)
target_link_libraries(MuxServiceTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismStreamContract PrismProtocolsCommon
    PrismLifecycle PrismTransport PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolTrojan PrismProtocolMux PrismRuntime)
