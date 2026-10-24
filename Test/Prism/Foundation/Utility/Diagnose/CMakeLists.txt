# diagnose 子模块测试
AddPrismTest(ObservabilityTest.cpp)
target_link_libraries(ObservabilityTest PRIVATE PrismFoundation PrismTestSupport)

AddPrismTest(ContextStateTest.cpp)
target_link_libraries(ContextStateTest PRIVATE PrismFoundation PrismTestSupport)

AddPrismTest(FieldCodecTest.cpp)
target_link_libraries(FieldCodecTest PRIVATE PrismFoundation PrismTestSupport)

AddPrismTest(ContextDecoderTest.cpp)
target_link_libraries(ContextDecoderTest PRIVATE PrismFoundation PrismTestSupport)

AddPrismTest(ContextLifetimeTest.cpp)
target_link_libraries(ContextLifetimeTest PRIVATE PrismFoundation PrismTestSupport)

AddPrismTest(SessionAuditTest.cpp)
target_link_libraries(SessionAuditTest PRIVATE
        PrismFoundation PrismTransport PrismRuntime PrismLifecycle PrismTestSupport)

AddPrismTest(DiagnoseFacadeTest.cpp)
target_link_libraries(DiagnoseFacadeTest PRIVATE
        PrismFoundation PrismTestSupport)

AddPrismTest(AsyncBackendInitTest.cpp)
target_link_libraries(AsyncBackendInitTest PRIVATE
        PrismFoundation PrismTestSupport)

AddPrismTest(AsyncBackendQueueTest.cpp)
target_link_libraries(AsyncBackendQueueTest PRIVATE
        PrismFoundation PrismTestSupport)

AddPrismTest(AsyncBackendFallbackTest.cpp)
target_link_libraries(AsyncBackendFallbackTest PRIVATE
        PrismFoundation PrismTestSupport)

AddPrismTest(AsyncBackendRotationTest.cpp)
target_link_libraries(AsyncBackendRotationTest PRIVATE
        PrismFoundation PrismTestSupport)

AddPrismTest(AsyncBackendShutdownTest.cpp)
target_link_libraries(AsyncBackendShutdownTest PRIVATE
        PrismFoundation PrismTestSupport)

AddPrismTest(LoggerTest.cpp)
target_link_libraries(LoggerTest PRIVATE PrismFoundation PrismTestSupport)

# 诊断测试使用后端静态实现。
foreach(PrismDiagnoseTest IN ITEMS
        ObservabilityTest ContextStateTest FieldCodecTest ContextDecoderTest ContextLifetimeTest
        SessionAuditTest DiagnoseFacadeTest AsyncBackendInitTest AsyncBackendQueueTest
        AsyncBackendFallbackTest AsyncBackendRotationTest AsyncBackendShutdownTest LoggerTest)
    target_link_libraries(${PrismDiagnoseTest} PRIVATE PrismDiagnoseBackend)
endforeach()

# Diagnose 内部状态机白盒用例单独取得 Src include root。
foreach(PrismDiagnoseWhiteboxTest IN ITEMS
        ContextDecoderTest
        ContextLifetimeTest
        SessionAuditTest
        DiagnoseFacadeTest
        AsyncBackendInitTest
        AsyncBackendQueueTest
        AsyncBackendFallbackTest
        AsyncBackendRotationTest
        AsyncBackendShutdownTest
        LoggerTest)
    target_include_directories(${PrismDiagnoseWhiteboxTest} PRIVATE "${PROJECT_SOURCE_DIR}/Src")
endforeach()

foreach(PrismDiagnoseRuntimeConsumer IN ITEMS
        SessionAuditTest
        DiagnoseFacadeTest
        AsyncBackendInitTest
        AsyncBackendQueueTest
        AsyncBackendRotationTest
        AsyncBackendShutdownTest
        LoggerTest)
    target_link_libraries(${PrismDiagnoseRuntimeConsumer} PRIVATE PrismApplication)
endforeach()
