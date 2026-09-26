# diagnose 子模块测试
AddPreviewTest(ObservabilityTest.cpp)
target_link_libraries(ObservabilityTest PRIVATE PreviewFoundation PreviewTestSupport)

AddPreviewTest(ContextStateTest.cpp)
target_link_libraries(ContextStateTest PRIVATE PreviewFoundation PreviewTestSupport)

AddPreviewTest(FieldCodecTest.cpp)
target_link_libraries(FieldCodecTest PRIVATE PreviewFoundation PreviewTestSupport)

AddPreviewTest(ContextDecoderTest.cpp)
target_link_libraries(ContextDecoderTest PRIVATE PreviewFoundation PreviewTestSupport)

AddPreviewTest(ContextLifetimeTest.cpp)
target_link_libraries(ContextLifetimeTest PRIVATE PreviewFoundation PreviewTestSupport)

AddPreviewTest(SessionAuditTest.cpp)
target_link_libraries(SessionAuditTest PRIVATE
        PreviewFoundation PreviewTransport PreviewRuntime PreviewTestSupport spdlog::spdlog)

AddPreviewTest(DiagnoseFacadeTest.cpp)
target_link_libraries(DiagnoseFacadeTest PRIVATE
        PreviewFoundation PreviewTestSupport spdlog::spdlog)

AddPreviewTest(AsyncBackendInitializationTest.cpp)
target_link_libraries(AsyncBackendInitializationTest PRIVATE
        PreviewFoundation PreviewTestSupport spdlog::spdlog)

AddPreviewTest(AsyncBackendQueueTest.cpp)
target_link_libraries(AsyncBackendQueueTest PRIVATE
        PreviewFoundation PreviewTestSupport spdlog::spdlog)

AddPreviewTest(AsyncBackendFallbackTest.cpp)
target_link_libraries(AsyncBackendFallbackTest PRIVATE
        PreviewFoundation PreviewTestSupport spdlog::spdlog)

AddPreviewTest(AsyncBackendRotationTest.cpp)
target_link_libraries(AsyncBackendRotationTest PRIVATE
        PreviewFoundation PreviewTestSupport spdlog::spdlog)

AddPreviewTest(AsyncBackendShutdownTest.cpp)
target_link_libraries(AsyncBackendShutdownTest PRIVATE
        PreviewFoundation PreviewTestSupport spdlog::spdlog)

AddPreviewTest(LoggerTest.cpp)
target_link_libraries(LoggerTest PRIVATE PreviewFoundation PreviewTestSupport spdlog::spdlog)
