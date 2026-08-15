prism_add_test(Config.cpp)
prism_add_test(Exception.cpp)
prism_add_test(Fault.cpp)
prism_add_test(CoreFault.cpp)
prism_add_test(CoreError.cpp)
prism_add_test(CoreTransmission.cpp)
prism_add_test(CoreAead.cpp)
prism_add_test(FeatureBitmapExtended.cpp)
prism_add_test(MemoryArena.cpp)
prism_add_test(PipelinePrimitives.cpp)
prism_add_test(StatsExtended.cpp)
prism_add_test(Trace.cpp)
prism_add_test(TraceSpdlogDeep.cpp)
prism_add_test(Base64Encode.cpp)
prism_add_test(AccountDirectory.cpp)
prism_add_test(AccountDirectoryPure.cpp)
prism_add_test(SchemeRouteTable.cpp)
# prism_add_test(Executor.cpp)
prism_add_test(ExecutorPure.cpp)
prism_add_test(BalancerDeep.cpp)
prism_add_test(RuntimeDeep.cpp)
prism_add_test(TrafficDeep.cpp)
# prism_add_test(TracePrefixCoro.cpp)

prism_add_test(MiddlewarePipelineTest.cpp)

prism_add_test(QpackInteropTest.cpp)

prism_add_test(QpackEncodeOut.cpp)

prism_add_test(TestRunnerDeep.cpp)
target_compile_options(TestRunnerDeep PRIVATE -O0 -fno-inline)

prism_add_test(TuicDgramDeep.cpp)
target_link_libraries(TuicDgramDeep PRIVATE vmtest_common)

prism_add_test(ConnDecoratorDeep.cpp)
target_link_libraries(ConnDecoratorDeep PRIVATE vmtest_common)
target_compile_options(ConnDecoratorDeep PRIVATE -O0 -fno-inline)

prism_add_test(TestCommonCodecDeep.cpp)
target_link_libraries(TestCommonCodecDeep PRIVATE vmtest_common)
target_compile_options(TestCommonCodecDeep PRIVATE -O0 -fno-inline)

prism_add_test(TestCommonCodecDeep2.cpp)
target_link_libraries(TestCommonCodecDeep2 PRIVATE vmtest_common)
target_compile_options(TestCommonCodecDeep2 PRIVATE -O0 -fno-inline)

prism_add_test(TestPsmTransport.cpp)
target_link_libraries(TestPsmTransport PRIVATE vmtest_common)
target_compile_options(TestPsmTransport PRIVATE -O0 -fno-inline)

prism_add_test(OwnershipAudit.cpp)

prism_add_test(MemoryPointerTest.cpp)
prism_add_test(MemoryLifecycleTest.cpp)
