AddPrismTest(MuxCodecTest.cpp)
target_link_libraries(MuxCodecTest PRIVATE PrismProtocolMux PrismTestSupport)
AddPrismTest(AnytlsWireTest.cpp)
target_link_libraries(AnytlsWireTest PRIVATE PrismProtocolMux)

if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(MuxPerf.cpp)
 target_link_libraries(MuxPerf PRIVATE PrismTransport PrismProtocolMux PrismProtocolTrojan PrismTestSupport)
    AddPrismTest(MuxRealRootMatrix.cpp)
 target_link_libraries(MuxRealRootMatrix PRIVATE PrismTransport PrismProtocolMux PrismProtocolTrojan PrismTestSupport)
    AddPrismTest(MuxRealRootLifecycleTest.cpp)
 target_link_libraries(MuxRealRootLifecycleTest PRIVATE PrismTransport PrismProtocolMux PrismProtocolTrojan PrismTestSupport)
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
target_link_libraries(MuxSessionTest PRIVATE PrismTransport PrismProtocolMux PrismTestSupport)
target_compile_options(MuxSessionTest PRIVATE -O0 -fno-inline)

AddPrismTest(MuxSessionDeep2.cpp)
target_link_libraries(MuxSessionDeep2 PRIVATE PrismTransport PrismProtocolMux PrismTestSupport)
target_compile_options(MuxSessionDeep2 PRIVATE -O0 -fno-inline)

AddPrismTest(MuxSessionDeep.cpp)
target_link_libraries(MuxSessionDeep PRIVATE PrismTransport PrismProtocolMux PrismTestSupport)
target_compile_options(MuxSessionDeep PRIVATE -O0 -fno-inline)

AddPrismTest(MuxWriteContract.cpp)
target_sources(MuxWriteContract PRIVATE MuxWriteContractLifecycle.cpp)
target_link_libraries(MuxWriteContract PRIVATE PrismTransport PrismProtocolMux PrismTestSupport)

AddPrismTest(MuxSessionOwnershipAuditTest.cpp)
target_sources(MuxSessionOwnershipAuditTest PRIVATE MuxSessionTestSupport.hpp)
target_link_libraries(MuxSessionOwnershipAuditTest PRIVATE PrismProtocolMux PrismTestSupport)

add_subdirectory(H2Mux)
add_subdirectory(Smux)
add_subdirectory(Yamux)

AddPrismTest(MuxRootOwnerTest.cpp)
target_sources(MuxRootOwnerTest PRIVATE MuxStreamAcceptInputTestSupport.hpp)
target_sources(MuxRootOwnerTest PRIVATE MuxRootFinishTest.cpp)
target_sources(MuxRootOwnerTest PRIVATE MuxRootCloseTestSupport.hpp)
target_link_libraries(MuxRootOwnerTest PRIVATE PrismProtocolTrojan PrismProtocolMux)
AddPrismTest(MuxRootCloseTest.cpp)
target_sources(MuxRootCloseTest PRIVATE MuxRootCloseTestSupport.hpp)
target_link_libraries(MuxRootCloseTest PRIVATE PrismProtocolTrojan PrismProtocolMux PrismTestSupport)
AddPrismTest(MuxServiceTest.cpp)
target_link_libraries(MuxServiceTest PRIVATE PrismProtocolTrojan PrismProtocolMux)
