AddProductionTest(ParcelDeep.cpp)
target_link_libraries(ParcelDeep PRIVATE ProductionTestSupport )

AddProductionTest(DuctDeep.cpp)
target_link_libraries(DuctDeep PRIVATE ProductionTestSupport )

AddPreviewTest(MuxCodecTest.cpp)
target_link_libraries(MuxCodecTest PRIVATE PreviewProtocolMux PreviewTestSupport)

AddProductionTest(MuxCoreDeep.cpp)
target_link_libraries(MuxCoreDeep PRIVATE ProductionTestSupport )

if(PRISM_ENABLE_BENCHMARK)
    AddPreviewTest(MuxPerf.cpp)
 target_link_libraries(MuxPerf PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)
endif()

AddPreviewTest(MuxSessionTest.cpp)
target_link_libraries(MuxSessionTest PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)
target_compile_options(MuxSessionTest PRIVATE -O0 -fno-inline)

AddPreviewTest(MuxSessionDeep2.cpp)
target_link_libraries(MuxSessionDeep2 PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)
target_compile_options(MuxSessionDeep2 PRIVATE -O0 -fno-inline)

AddPreviewTest(MuxSessionDeep.cpp)
target_link_libraries(MuxSessionDeep PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)
target_compile_options(MuxSessionDeep PRIVATE -O0 -fno-inline)

AddPreviewTest(MuxWriteContract.cpp)
target_link_libraries(MuxWriteContract PRIVATE PreviewTransport PreviewProtocolMux PreviewTestSupport)
