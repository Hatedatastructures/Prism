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
        PrismFoundation PrismTransport PrismRuntime PrismTestSupport spdlog::spdlog)

AddPrismTest(DiagnoseFacadeTest.cpp)
target_link_libraries(DiagnoseFacadeTest PRIVATE
        PrismFoundation PrismTestSupport spdlog::spdlog)

AddPrismTest(AsyncBackendInitializationTest.cpp)
target_link_libraries(AsyncBackendInitializationTest PRIVATE
        PrismFoundation PrismTestSupport spdlog::spdlog)

AddPrismTest(AsyncBackendQueueTest.cpp)
target_link_libraries(AsyncBackendQueueTest PRIVATE
        PrismFoundation PrismTestSupport spdlog::spdlog)

AddPrismTest(AsyncBackendFallbackTest.cpp)
target_link_libraries(AsyncBackendFallbackTest PRIVATE
        PrismFoundation PrismTestSupport spdlog::spdlog)

AddPrismTest(AsyncBackendRotationTest.cpp)
target_link_libraries(AsyncBackendRotationTest PRIVATE
        PrismFoundation PrismTestSupport spdlog::spdlog)

AddPrismTest(AsyncBackendShutdownTest.cpp)
target_link_libraries(AsyncBackendShutdownTest PRIVATE
        PrismFoundation PrismTestSupport spdlog::spdlog)

AddPrismTest(LoggerTest.cpp)
target_link_libraries(LoggerTest PRIVATE PrismFoundation PrismTestSupport spdlog::spdlog)
