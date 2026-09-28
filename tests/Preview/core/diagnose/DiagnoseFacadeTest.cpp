/**
 * @file DiagnoseFacadeTest.cpp
 * @brief Diagnose facade 的格式、Context 和提交语义测试。
 */

#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <TestSupport/Preview/DiagnoseTestEnvironment.hpp>

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

    TEST(PreviewDiagnose, FacadeFormatsOnCallerAndPreservesSubmissionSemantics)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"facade", 128U};
        Environment.Configuration().Logging.Level = Preview::Diagnose::LogLevel::Trace;
        ASSERT_TRUE(Environment.Install().has_value());
        const auto Context = Preview::Diagnose::ContextState::Empty()
                                 .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{2})
                                 .With(Preview::Diagnose::Fields::Session, Preview::SessionId{3});

        const auto Debug = Preview::Diagnose::Debug(Context, "DebugId={}", 1U);
        const auto Info = Preview::Diagnose::Info("RuntimeReady Port={}", 1080U);
        const auto Access = Preview::Diagnose::Access(Context, "RequestAccepted Bytes={}", 12U);
        const auto Warn = Preview::Diagnose::Warn("WarnCode={}", 7U);
        const auto Error = Preview::Diagnose::Error(Context, "ErrorCode={}", 8U);
        const auto Critical = Preview::Diagnose::Critical("CriticalCode={}", 9U);
        const auto Audit = Preview::Diagnose::Audit(Context, "SessionClosed");
        const auto Secret = Preview::Diagnose::Info("Token=facade-canary");
        const auto Multiline = Preview::Diagnose::Info("FirstLine\nSecondLine");

        EXPECT_EQ(Debug.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Info.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Access.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Warn.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Error.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Critical.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Audit.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Secret.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Multiline.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_LT(Debug.Sequence, Info.Sequence);
        EXPECT_LT(Info.Sequence, Access.Sequence);
        EXPECT_LT(Access.Sequence, Warn.Sequence);
        EXPECT_LT(Warn.Sequence, Error.Sequence);
        EXPECT_LT(Error.Sequence, Critical.Sequence);
        EXPECT_LT(Critical.Sequence, Audit.Sequence);

        EXPECT_EQ(Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2}).Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Preview::Diagnose::Info("after shutdown").Status,
                  Preview::Diagnose::SubmissionStatus::Stopped);

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
        EXPECT_NE(Contents.find("token=<redacted>"), std::string::npos);
        EXPECT_EQ(Contents.find("facade-canary"), std::string::npos);
        EXPECT_NE(Contents.find("FirstLine\\nSecondLine"), std::string::npos);
    }

    TEST(PreviewDiagnose, PascalCaseTokenFormatsOnlyControlledNames)
    {
        EXPECT_EQ(Preview::Diagnose::PascalCaseToken("client_hello_timeout"),
                  "ClientHelloTimeout");
        EXPECT_EQ(Preview::Diagnose::PascalCaseToken("hysteria2"), "Hysteria2");
        EXPECT_EQ(Preview::Diagnose::LogLevelName(Preview::Diagnose::LogLevel::Trace), "Trace");
        EXPECT_EQ(Preview::Diagnose::LogLevelName(Preview::Diagnose::LogLevel::Debug), "Debug");
        EXPECT_EQ(Preview::Diagnose::LogLevelName(Preview::Diagnose::LogLevel::Info), "Info");
        EXPECT_EQ(Preview::Diagnose::LogLevelName(Preview::Diagnose::LogLevel::Access), "Access");
        EXPECT_EQ(Preview::Diagnose::LogLevelName(Preview::Diagnose::LogLevel::Warn), "Warn");
        EXPECT_EQ(Preview::Diagnose::LogLevelName(Preview::Diagnose::LogLevel::Error), "Error");
        EXPECT_EQ(Preview::Diagnose::LogLevelName(Preview::Diagnose::LogLevel::Critical),
                  "Critical");
    }

    TEST(PreviewDiagnose, IsEnabledReportsInstalledOrdinaryThreshold)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"level-query"};
        ASSERT_TRUE(Environment.Install().has_value());
        EXPECT_TRUE(Preview::Diagnose::IsEnabled(Preview::Diagnose::LogLevel::Info));
        EXPECT_FALSE(Preview::Diagnose::IsEnabled(Preview::Diagnose::LogLevel::Debug));
        EXPECT_FALSE(Preview::Diagnose::IsEnabled(Preview::Diagnose::LogLevel::Trace));
        EXPECT_TRUE(Preview::Diagnose::IsEnabled(Preview::Diagnose::LogLevel::Access));
    }

} // namespace
