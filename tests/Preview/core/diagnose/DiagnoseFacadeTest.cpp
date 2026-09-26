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

        const auto Debug = Preview::Diagnose::Debug(Context, "debug id={}", 1U);
        const auto Info = Preview::Diagnose::Info("ready port={}", 1080U);
        const auto Access = Preview::Diagnose::Access(Context, "accepted bytes={}", 12U);
        const auto Warn = Preview::Diagnose::Warn("warn code={}", 7U);
        const auto Error = Preview::Diagnose::Error(Context, "error code={}", 8U);
        const auto Critical = Preview::Diagnose::Critical("critical code={}", 9U);
        const auto Audit = Preview::Diagnose::Audit(Context, "event={}", "session_closed");
        const auto Secret = Preview::Diagnose::Info("token=facade-canary");
        const auto Multiline = Preview::Diagnose::Info("first line\nsecond line");

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
        EXPECT_NE(Contents.find("[W2][S3] debug id=1"), std::string::npos);
        EXPECT_NE(Contents.find("ready port=1080"), std::string::npos);
        EXPECT_NE(Contents.find("[W2][S3] [access] accepted bytes=12"), std::string::npos);
        EXPECT_NE(Contents.find("[warning] warn code=7"), std::string::npos);
        EXPECT_NE(Contents.find("[error] [W2][S3] error code=8"), std::string::npos);
        EXPECT_NE(Contents.find("[critical] critical code=9"), std::string::npos);
        EXPECT_NE(Contents.find("[W2][S3] [access] event=session_closed"), std::string::npos);
        EXPECT_NE(Contents.find("token=<redacted>"), std::string::npos);
        EXPECT_EQ(Contents.find("facade-canary"), std::string::npos);
        EXPECT_NE(Contents.find("first line\\nsecond line"), std::string::npos);
    }

} // namespace
