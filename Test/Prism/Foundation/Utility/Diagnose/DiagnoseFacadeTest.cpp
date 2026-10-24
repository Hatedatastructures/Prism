/**
 * @file DiagnoseFacadeTest.cpp
 * @brief Diagnose facade 的格式、Context 和提交语义测试。
 */

#include <gtest/gtest.h>

#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <TestSupport/Prism/DiagnoseTestEnvironment.hpp>

#include <chrono>
#include <fstream>
#include <iterator>
#include <regex>
#include <string>

namespace
{

    auto ReadFile(const std::filesystem::path &Path) -> std::string
    {
        std::ifstream Input(Path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(Input),
                           std::istreambuf_iterator<char>());
    }

    TEST(PrismDiagnose, FacadeFormatsOnCallerAndPreservesSubmissionSemantics)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"facade", 128U};
        Environment.Configuration().Logging.Level = Prism::Diagnose::LogLevel::Trace;
        ASSERT_TRUE(Environment.Install().has_value());
        const auto Context = Prism::Diagnose::ContextState::Empty()
                                 .With(Prism::Diagnose::Fields::Worker, Prism::WorkerId{2})
                                 .With(Prism::Diagnose::Fields::Session, Prism::SessionId{3});

        const auto Debug = Prism::Diagnose::Debug(Context, "DebugId={}", 1U);
        const auto Info = Prism::Diagnose::Info("RuntimeReady Port={}", 1080U);
        const auto Access = Prism::Diagnose::Access(Context, "RequestAccepted Bytes={}", 12U);
        const auto Warn = Prism::Diagnose::Warn("WarnCode={}", 7U);
        const auto Error = Prism::Diagnose::Error(Context, "ErrorCode={}", 8U);
        const auto Critical = Prism::Diagnose::Critical("CriticalCode={}", 9U);
        const auto Audit = Prism::Diagnose::Audit(Context, "SessionClosed");
        const auto Secret = Prism::Diagnose::Info("Token=facade-canary");
        const auto Multiline = Prism::Diagnose::Info("FirstLine\nSecondLine");

        EXPECT_EQ(Debug.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Info.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Access.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Warn.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Error.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Critical.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Audit.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Secret.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Multiline.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_LT(Debug.Sequence, Info.Sequence);
        EXPECT_LT(Info.Sequence, Access.Sequence);
        EXPECT_LT(Access.Sequence, Warn.Sequence);
        EXPECT_LT(Warn.Sequence, Error.Sequence);
        EXPECT_LT(Error.Sequence, Critical.Sequence);
        EXPECT_LT(Critical.Sequence, Audit.Sequence);

        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
        EXPECT_EQ(Flushed.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_FALSE(Flushed.Accepted());
        EXPECT_EQ(Flushed.Sequence, Multiline.Sequence);
        EXPECT_EQ(Environment.Runtime().Written(), 9U);
        const auto Closed = Environment.Runtime().Shutdown();
        EXPECT_EQ(Closed.Status, Prism::Diagnose::SubmissionStatus::Closed);
        EXPECT_FALSE(Closed.Accepted());
        EXPECT_EQ(Closed.Sequence, Multiline.Sequence);
        EXPECT_EQ(Prism::Diagnose::Info("after shutdown").Status,
                  Prism::Diagnose::SubmissionStatus::Stopped);

        const auto Contents = ReadFile(Environment.Configuration().Logging.Directory /
                                       Environment.Configuration().Logging.FileName);
        EXPECT_NE(Contents.find("[Debug] [W2][S3] DebugId=1"), std::string::npos);
        EXPECT_NE(Contents.find("[Info] RuntimeReady Port=1080"), std::string::npos);
        EXPECT_NE(Contents.find("[Access] [W2][S3] RequestAccepted Bytes=12"), std::string::npos);
        EXPECT_NE(Contents.find("[Warn] WarnCode=7"), std::string::npos);
        EXPECT_NE(Contents.find("[Error] [W2][S3] ErrorCode=8"), std::string::npos);
        EXPECT_NE(Contents.find("[Critical] CriticalCode=9"), std::string::npos);
        EXPECT_NE(Contents.find("[Access] [W2][S3] SessionClosed"), std::string::npos);
        EXPECT_FALSE(std::regex_search(Contents, std::regex(R"(\[\s*[0-9]{1,8}\s*\])")));
        EXPECT_NE(Contents.find("Token=<redacted>"), std::string::npos);
        EXPECT_EQ(Contents.find("facade-canary"), std::string::npos);
        EXPECT_NE(Contents.find("FirstLine\\nSecondLine"), std::string::npos);
    }

    TEST(PrismDiagnose, FacadeOwnsTextArgumentsBeforeReturning)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"argument-snapshot", 128U};
        ASSERT_TRUE(Environment.Install().has_value());
        std::string Argument{"captured-before-return"};
        const auto Submitted = Prism::Diagnose::Info("Captured={}", Argument);
        ASSERT_EQ(Submitted.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        Argument = "mutated-after-submit";

        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
        ASSERT_EQ(Flushed.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_EQ(Flushed.Sequence, Submitted.Sequence);
        EXPECT_EQ(Environment.Runtime().Written(), 1U);
        const auto Closed = Environment.Runtime().Shutdown();
        EXPECT_EQ(Closed.Status, Prism::Diagnose::SubmissionStatus::Closed);

        const auto Contents = ReadFile(Environment.Configuration().Logging.Directory /
                                       Environment.Configuration().Logging.FileName);
        EXPECT_NE(Contents.find("Captured=captured-before-return"), std::string::npos);
        EXPECT_EQ(Contents.find("mutated-after-submit"), std::string::npos);
    }

    TEST(PrismDiagnose, PascalCaseTokenFormatsOnlyControlledNames)
    {
        EXPECT_EQ(Prism::Diagnose::PascalCaseToken("client_hello_timeout"),
                  "ClientHelloTimeout");
        EXPECT_EQ(Prism::Diagnose::PascalCaseToken("hysteria2"), "Hysteria2");
        EXPECT_EQ(Prism::Diagnose::LogLevelName(Prism::Diagnose::LogLevel::Trace), "Trace");
        EXPECT_EQ(Prism::Diagnose::LogLevelName(Prism::Diagnose::LogLevel::Debug), "Debug");
        EXPECT_EQ(Prism::Diagnose::LogLevelName(Prism::Diagnose::LogLevel::Info), "Info");
        EXPECT_EQ(Prism::Diagnose::LogLevelName(Prism::Diagnose::LogLevel::Access), "Access");
        EXPECT_EQ(Prism::Diagnose::LogLevelName(Prism::Diagnose::LogLevel::Warn), "Warn");
        EXPECT_EQ(Prism::Diagnose::LogLevelName(Prism::Diagnose::LogLevel::Error), "Error");
        EXPECT_EQ(Prism::Diagnose::LogLevelName(Prism::Diagnose::LogLevel::Critical),
                  "Critical");
    }

    TEST(PrismDiagnose, IsEnabledReportsInstalledOrdinaryThreshold)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"level-query"};
        ASSERT_TRUE(Environment.Install().has_value());
        EXPECT_TRUE(Prism::Diagnose::IsEnabled(Prism::Diagnose::LogLevel::Info));
        EXPECT_FALSE(Prism::Diagnose::IsEnabled(Prism::Diagnose::LogLevel::Debug));
        EXPECT_FALSE(Prism::Diagnose::IsEnabled(Prism::Diagnose::LogLevel::Trace));
        EXPECT_TRUE(Prism::Diagnose::IsEnabled(Prism::Diagnose::LogLevel::Access));
    }

    TEST(PrismDiagnose, CapturedIndependentContextPinsCreationEpoch)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"captured-epoch", 32U};
        ASSERT_TRUE(Environment.Install().has_value());
        auto Captured = Prism::Diagnose::CaptureCurrentContext();
        ASSERT_TRUE(Captured.RenderEpoch());
        const auto InitialEpoch = Environment.Runtime().CurrentEpoch();
        EXPECT_EQ(Captured.RenderEpoch().get(), InitialEpoch.get());

        auto UpdatedConfiguration = Environment.Configuration();
        UpdatedConfiguration.Logging.Level = Prism::Diagnose::LogLevel::Debug;
        UpdatedConfiguration.Mode = Prism::Diagnose::RenderMode::Structured;
        const auto Prepared =
            Environment.PrepareEpochAfterRegistryContention(UpdatedConfiguration);
        ASSERT_TRUE(Prepared.has_value());
        const auto UpdatedEpoch = *Prepared;
        ASSERT_TRUE(Environment.Runtime().PublishEpoch(UpdatedEpoch));
        auto CapturedAfterChange = Prism::Diagnose::CaptureCurrentContext();
        ASSERT_TRUE(CapturedAfterChange.RenderEpoch());
        EXPECT_EQ(Captured.RenderEpoch().get(), InitialEpoch.get());
        EXPECT_EQ(CapturedAfterChange.RenderEpoch().get(), UpdatedEpoch.get());

        const auto OldFiltered = Prism::Diagnose::Debug(Captured, "old-epoch-filtered");
        const auto NewAccepted = Prism::Diagnose::Debug(CapturedAfterChange, "new-epoch-debug");
        EXPECT_EQ(OldFiltered.Status, Prism::Diagnose::SubmissionStatus::Filtered);
        EXPECT_EQ(NewAccepted.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2}).Status,
            Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status,
            Prism::Diagnose::SubmissionStatus::Closed);
    }

} // namespace
