AddPreviewTest(MuxCodecTest.cpp)
target_link_libraries(MuxCodecTest PRIVATE PreviewProtocolMux PreviewTestSupport)
AddPreviewTest(AnytlsWireTest.cpp)
target_link_libraries(AnytlsWireTest PRIVATE PreviewProtocolMux)

if(PRISM_ENABLE_BENCHMARK)
    AddPreviewTest(MuxPerf.cpp)
 target_link_libraries(MuxPerf PRIVATE PreviewTransport PreviewProtocolMux PreviewProtocolTrojan PreviewTestSupport)
    AddPreviewTest(MuxRealRootMatrix.cpp)
 target_link_libraries(MuxRealRootMatrix PRIVATE PreviewTransport PreviewProtocolMux PreviewProtocolTrojan PreviewTestSupport)
    AddPreviewTest(MuxRealRootLifecycleTest.cpp)
 target_link_libraries(MuxRealRootLifecycleTest PRIVATE PreviewTransport PreviewProtocolMux PreviewProtocolTrojan PreviewTestSupport)
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

AddPreviewTest(MuxSessionTest.cpp)
target_sources(MuxSessionTest PRIVATE MuxSessionTestSupport.hpp)
target_link_libraries(MuxSessionTest PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)
target_compile_options(MuxSessionTest PRIVATE -O0 -fno-inline)

AddPreviewTest(MuxSessionDeep2.cpp)
target_link_libraries(MuxSessionDeep2 PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)
target_compile_options(MuxSessionDeep2 PRIVATE -O0 -fno-inline)

AddPreviewTest(MuxSessionDeep.cpp)
target_link_libraries(MuxSessionDeep PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)
target_compile_options(MuxSessionDeep PRIVATE -O0 -fno-inline)

AddPreviewTest(MuxWriteContract.cpp)
target_sources(MuxWriteContract PRIVATE MuxWriteContractLifecycle.cpp)
target_link_libraries(MuxWriteContract PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)

AddPreviewTest(MuxSessionOwnershipAuditTest.cpp)
target_sources(MuxSessionOwnershipAuditTest PRIVATE MuxSessionTestSupport.hpp)
target_link_libraries(MuxSessionOwnershipAuditTest PRIVATE PreviewProtocolMux PreviewTestSupport)

add_subdirectory(H2Mux)
add_subdirectory(Smux)
add_subdirectory(Yamux)

AddPreviewTest(MuxRootOwnerTest.cpp)
target_sources(MuxRootOwnerTest PRIVATE MuxStreamAcceptInputTestSupport.hpp)
target_sources(MuxRootOwnerTest PRIVATE MuxRootFinishTest.cpp)
target_link_libraries(MuxRootOwnerTest PRIVATE PreviewProtocolTrojan PreviewProtocolMux)
AddPreviewTest(MuxServiceTest.cpp)
target_link_libraries(MuxServiceTest PRIVATE PreviewProtocolTrojan PreviewProtocolMux)
