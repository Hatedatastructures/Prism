/**
 * @file LoggerTest.cpp
 * @brief Facade 与 spdlog backend 集成测试。
 */
#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <TestSupport/Preview/DiagnoseTestEnvironment.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

namespace
{

    auto CountText(const std::string_view Text, const std::string_view Needle) -> std::size_t
    {
        std::size_t Count = 0U;
        std::size_t Offset = 0U;
        while ((Offset = Text.find(Needle, Offset)) != std::string_view::npos)
        {
            ++Count;
            Offset += Needle.size();
        }
        return Count;
    }

    TEST(PreviewLogger, WritesStructuredFieldsAndReleasesFileAfterShutdown)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"logger-facade"};
        Environment.Configuration().Mode = Preview::Diagnose::RenderMode::Structured;
        ASSERT_TRUE(Environment.Install().has_value());

        const auto Context = Preview::Diagnose::ContextState::Empty()
                                 .With(Preview::Diagnose::Fields::Worker,
                                       Preview::WorkerId{202})
                                 .With(Preview::Diagnose::Fields::Session,
                                       Preview::SessionId{303})
                                 .With(Preview::Diagnose::Fields::Process,
                                       Preview::ProcessId{404})
                                 .With(Preview::Diagnose::Fields::Task,
                                       Preview::TaskId{505})
                                 .With(Preview::Diagnose::Fields::Protocol,
                                       std::string_view{"Vless"})
                                 .With(Preview::Diagnose::Fields::NativeError,
                                       std::string_view{"password=plain-secret"});
        const auto Warning = Preview::Diagnose::Warn(
            Context, "TlsFailure Status={}", "Failed");
        const auto Audit = Preview::Diagnose::Audit(
            Context, "LoggerAudit Status={}", "Closed");
        EXPECT_EQ(Warning.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Audit.Status, Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2}).Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);

        const auto LogPath = Environment.Configuration().Logging.Directory /
                             Environment.Configuration().Logging.FileName;
        std::ifstream Input(LogPath, std::ios::binary);
        ASSERT_TRUE(Input.is_open());
        const std::string Contents{std::istreambuf_iterator<char>{Input},
                                   std::istreambuf_iterator<char>{}};
        EXPECT_EQ(CountText(Contents, "TlsFailure Status=Failed"), 1U);
        EXPECT_EQ(CountText(Contents, "LoggerAudit Status=Closed"), 1U);
        EXPECT_NE(Contents.find("\"Worker\":202"), std::string::npos);
        EXPECT_NE(Contents.find("\"Session\":303"), std::string::npos);
        EXPECT_NE(Contents.find("\"Sequence\":"), std::string::npos);
        EXPECT_NE(Contents.find("\"Kind\":\"Audit\""), std::string::npos);
        EXPECT_NE(Contents.find("\"Level\":\"Warn\""), std::string::npos);
        EXPECT_NE(Contents.find("\"Level\":\"Access\""), std::string::npos);
        EXPECT_NE(Contents.find("Protocol"), std::string::npos);
        EXPECT_NE(Contents.find("password=<redacted>"), std::string::npos);
        EXPECT_EQ(Contents.find("plain-secret"), std::string::npos);

        Input.close();
        std::ofstream Reopened(LogPath, std::ios::binary | std::ios::app);
        EXPECT_TRUE(Reopened.is_open());
    }

} // namespace
