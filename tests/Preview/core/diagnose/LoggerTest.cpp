/**
 * @file LoggerTest.cpp
 * @brief Preview 诊断日志格式、轮转和敏感信息边界测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include <Preview/Foundation/Utility/Diagnose/Log.hpp>
#include <Preview/Foundation/Utility/Diagnose/Logger.hpp>
#include <Preview/Runtime/SessionControl.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>

namespace
{

    auto MakeDirectory(const std::string_view Suffix) -> std::filesystem::path
    {
        const auto Stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        return std::filesystem::temp_directory_path() /
               ("prism-preview-logger-" + std::string(Suffix) + "-" + std::to_string(Stamp));
    }

    auto ReadFile(const std::filesystem::path &Path) -> std::string
    {
        std::ifstream Input(Path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(Input), std::istreambuf_iterator<char>());
    }

    auto Cleanup(const std::filesystem::path &Directory) -> void
    {
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);
        ASSERT_FALSE(Error) << Error.message();
    }

    auto CountText(const std::string_view Text, const std::string_view Needle) -> std::size_t
    {
        std::size_t Count = 0;
        std::size_t Position = 0;
        while ((Position = Text.find(Needle, Position)) != std::string_view::npos)
        {
            ++Count;
            Position += Needle.size();
        }
        return Count;
    }

    TEST(PreviewLogger, WritesHumanReadableEventLevelAndCorrelationFields)
    {
        const auto Directory = MakeDirectory("human");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        Options.FileName = "preview.log";
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        auto Context = std::make_shared<Preview::Diagnose::TraceContext>();
        Context->SetCorrelation(Preview::RequestId{101});
        Context->SetWorker(Preview::WorkerId{202});
        Context->SetSession(Preview::SessionId{303});
        ASSERT_EQ(Preview::Diagnose::Info(Logger, Context, "event=runtime_ready status=healthy"),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        Logger->Stop();

        const auto Contents = ReadFile(Directory / "preview.log");
        EXPECT_NE(Contents.find("[Info]"), std::string::npos);
        EXPECT_NE(Contents.find("[Event=runtime_ready]"), std::string::npos);
        EXPECT_NE(Contents.find("[Correlation=101]"), std::string::npos);
        EXPECT_NE(Contents.find("[Worker=202]"), std::string::npos);
        EXPECT_NE(Contents.find("[Session=303]"), std::string::npos);
        EXPECT_EQ(Contents.find("[Stream="), std::string::npos);

        Logger.reset();
        Cleanup(Directory);
    }

    TEST(PreviewLogger, StopReleasesFileWhileOwnerRemainsAlive)
    {
        const auto Directory = MakeDirectory("stop-close");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        const auto Written = Logger->TryWrite(Preview::Diagnose::LogLevel::Info,
                                               "event=stop_close_fixture", {});
        Logger->Stop();
        std::error_code RemoveError;
        const auto Removed = std::filesystem::remove_all(Directory, RemoveError);
        Logger.reset();
        Cleanup(Directory);

        EXPECT_EQ(Written, Preview::Diagnose::EnqueueStatus::Accepted);
        EXPECT_FALSE(RemoveError) << RemoveError.message();
        EXPECT_GT(Removed, 0U);
    }

    TEST(PreviewLogger, RedactsSecretsBeforeAsynchronousQueueing)
    {
        const auto Directory = MakeDirectory("redaction");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        ASSERT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Warn,
                                   "event=auth_failed password=plain-secret token=token-secret",
                                   {}),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        Logger->Stop();

        const auto Contents = ReadFile(Directory / "preview.log");
        EXPECT_NE(Contents.find("password=<redacted>"), std::string::npos);
        EXPECT_NE(Contents.find("token=<redacted>"), std::string::npos);
        EXPECT_EQ(Contents.find("plain-secret"), std::string::npos);
        EXPECT_EQ(Contents.find("token-secret"), std::string::npos);

        Logger.reset();
        Cleanup(Directory);
    }

    TEST(PreviewLogger, WritesStructuredTlsTraceFields)
    {
        const auto Directory = MakeDirectory("structured-trace");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        Preview::Statistics::TraceSnapshot Trace;
        Trace.Task = Preview::TaskId{11};
        Trace.Generation = Preview::GenerationId{12};
        Trace.Carrier = "native";
        Trace.Protocol = "vless";
        Trace.TlsVersion = "TLS1.3";
        Trace.Stage = "handshake";
        Trace.Status = "failed";
        Trace.FaultCode = "tls_alert";
        Trace.NativeError = "alert:40";
        Trace.ElapsedMs = 17;
        ASSERT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Warn,
                                   "event=tls_failure", Trace),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        Logger->Stop();

        const auto Contents = ReadFile(Directory / "preview.log");
        EXPECT_NE(Contents.find("[Task=11]"), std::string::npos);
        EXPECT_NE(Contents.find("[Generation=12]"), std::string::npos);
        EXPECT_NE(Contents.find("[Carrier=native]"), std::string::npos);
        EXPECT_NE(Contents.find("[Protocol=vless]"), std::string::npos);
        EXPECT_NE(Contents.find("[TlsVersion=TLS1.3]"), std::string::npos);
        EXPECT_NE(Contents.find("[FaultCode=tls_alert]"), std::string::npos);
        EXPECT_NE(Contents.find("[NativeError=alert:40]"), std::string::npos);
        EXPECT_NE(Contents.find("[ElapsedMs=17]"), std::string::npos);

        Logger.reset();
        Cleanup(Directory);
    }

    TEST(PreviewLogger, ArchivesLegacyEpochLogBeforeCreatingCurrentLog)
    {
        const auto Directory = MakeDirectory("legacy");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);
        std::filesystem::create_directories(Directory, Error);
        ASSERT_FALSE(Error) << Error.message();

        const auto LogPath = Directory / "preview.log";
        {
            std::ofstream Legacy(LogPath, std::ios::binary);
            Legacy << "1710000000 [info] event=old_epoch message=legacy\n";
        }

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);
        ASSERT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Info,
                                   "event=current message=new_format", {}),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        Logger->Stop();

        const auto Current = ReadFile(LogPath);
        const auto Legacy = ReadFile(Directory / "preview.log.legacy");
        EXPECT_NE(Current.find("event=current"), std::string::npos);
        EXPECT_EQ(Current.find("old_epoch"), std::string::npos);
        EXPECT_NE(Legacy.find("1710000000"), std::string::npos);
        EXPECT_NE(Legacy.find("old_epoch"), std::string::npos);

        Logger.reset();
        Cleanup(Directory);
    }

    TEST(PreviewLogger, EmitsSessionCloseAccessExactlyOncePerCorrelation)
    {
        const auto Directory = MakeDirectory("access");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        Preview::Statistics::TraceSnapshot Trace;
        Trace.Correlation = Preview::RequestId{404};
        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Access,
                                   "event=session_closed status=success",
                                   Trace),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Access,
                                   "event=session_closed status=success",
                                   Trace),
                  Preview::Diagnose::EnqueueStatus::Filtered);
        Logger->Stop();

        const auto Contents = ReadFile(Directory / "preview.log");
        EXPECT_NE(Contents.find("stage=close"), std::string::npos);
        EXPECT_EQ(Contents.find("stage=close"), Contents.rfind("stage=close"));
        EXPECT_NE(Contents.find("[Correlation=404]"), std::string::npos);
        EXPECT_EQ(Contents.find("[Correlation=404]"), Contents.rfind("[Correlation=404]"));

        Logger.reset();
        Cleanup(Directory);
    }

    TEST(PreviewLogger, KeepsSessionCloseOncePerSessionForEqualLocalTaskIds)
    {
        const auto Directory = MakeDirectory("session-identity");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        namespace Net = boost::asio;
        Net::io_context Ioc;
        Preview::Runtime::SessionControl FirstControl(Ioc.get_executor());
        Preview::Runtime::SessionControl SecondControl(Ioc.get_executor());

        Preview::Lifecycle::TaskRequest FirstRequest;
        FirstRequest.Identity.SessionId = Preview::SessionId{101};
        FirstRequest.Identity.WorkerId = Preview::WorkerId{3};
        FirstRequest.Identity.Generation = Preview::GenerationId{7};
        ASSERT_TRUE(FirstControl.Start(
            std::move(FirstRequest), []() -> Net::awaitable<void> { co_return; }()));

        Preview::Lifecycle::TaskRequest SecondRequest;
        SecondRequest.Identity.SessionId = Preview::SessionId{202};
        SecondRequest.Identity.WorkerId = Preview::WorkerId{3};
        SecondRequest.Identity.Generation = Preview::GenerationId{8};
        ASSERT_TRUE(SecondControl.Start(
            std::move(SecondRequest), []() -> Net::awaitable<void> { co_return; }()));

        Ioc.run();

        const auto FirstIdentity = FirstControl.CurrentIdentity();
        const auto SecondIdentity = SecondControl.CurrentIdentity();
        ASSERT_TRUE(static_cast<bool>(FirstIdentity.TaskId));
        ASSERT_TRUE(static_cast<bool>(SecondIdentity.TaskId));
        EXPECT_NE(FirstIdentity.TaskId, SecondIdentity.TaskId);
        ASSERT_NE(FirstIdentity.SessionId, SecondIdentity.SessionId);

        Preview::Statistics::TraceSnapshot FirstTrace;
        FirstTrace.Correlation = Preview::RequestId{FirstIdentity.TaskId.Value()};
        FirstTrace.Worker = FirstIdentity.WorkerId;
        FirstTrace.Session = FirstIdentity.SessionId;
        Preview::Statistics::TraceSnapshot SecondTrace;
        SecondTrace.Correlation = Preview::RequestId{SecondIdentity.TaskId.Value()};
        SecondTrace.Worker = SecondIdentity.WorkerId;
        SecondTrace.Session = SecondIdentity.SessionId;

        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Access,
                                   "event=session_closed status=success",
                                   FirstTrace),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Access,
                                   "event=session_closed status=success",
                                   SecondTrace),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Access,
                                   "event=session_closed status=success",
                                   FirstTrace),
                  Preview::Diagnose::EnqueueStatus::Filtered);
        Logger->Stop();

        const auto Contents = ReadFile(Directory / "preview.log");
        EXPECT_EQ(CountText(Contents, "stage=close"), 2U);
        EXPECT_EQ(CountText(Contents, "[Session=101]"), 1U);
        EXPECT_EQ(CountText(Contents, "[Session=202]"), 1U);

        Logger.reset();
        Cleanup(Directory);
    }

    TEST(PreviewLogger, KeepsSessionCloseOnceWhenWorkerAndTaskChange)
    {
        const auto Directory = MakeDirectory("session-close-key");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        Preview::Statistics::TraceSnapshot FirstTrace;
        FirstTrace.Worker = Preview::WorkerId{3};
        FirstTrace.Session = Preview::SessionId{303};
        FirstTrace.Correlation = Preview::RequestId{1};
        Preview::Statistics::TraceSnapshot SecondTrace;
        SecondTrace.Worker = Preview::WorkerId{9};
        SecondTrace.Session = Preview::SessionId{303};
        SecondTrace.Correlation = Preview::RequestId{2};

        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Access,
                                   "event=session_closed status=success",
                                   FirstTrace),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Access,
                                   "event=session_closed status=success",
                                   SecondTrace),
                  Preview::Diagnose::EnqueueStatus::Filtered);
        Logger->Stop();

        const auto Contents = ReadFile(Directory / "preview.log");
        EXPECT_EQ(CountText(Contents, "stage=close"), 1U);
        EXPECT_NE(Contents.find("[Session=303]"), std::string::npos);

        Logger.reset();
        Cleanup(Directory);
    }

    TEST(PreviewLogger, RotatesOnlyCurrentFormatFiles)
    {
        const auto Directory = MakeDirectory("rotation");
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        Options.RotateBytes = 4096;
        Options.RotateFiles = 2;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        const std::string Payload(2200, 'x');
        ASSERT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Info,
                                   "event=rotation_first " + Payload, {}),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        ASSERT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Info,
                                   "event=rotation_second " + Payload, {}),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        ASSERT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Info,
                                   "event=rotation_third " + Payload, {}),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        Logger->Stop();

        ASSERT_TRUE(std::filesystem::exists(Directory / "preview.log.1"));
        EXPECT_NE(ReadFile(Directory / "preview.log").find("# PrismPreview log format=v2"),
                  std::string::npos);
        EXPECT_NE(ReadFile(Directory / "preview.log.1").find("# PrismPreview log format=v2"),
                  std::string::npos);

        Logger.reset();
        Cleanup(Directory);
    }

} // namespace
