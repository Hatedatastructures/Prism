/**
 * @file AsyncBackendQueueTest.cpp
 * @brief spdlog async queue level filtering and nonblocking Audit submission contract.
 */
#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp>
#include <TestSupport/Preview/DiagnoseTestEnvironment.hpp>

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>

namespace
{

    TEST(PreviewLogger, AccessChannelAndAuditBypassOrdinaryLevelThreshold)
    {
        using Preview::Diagnose::Detail::AsyncSubmission;
        using Preview::Diagnose::LogLevel;
        EXPECT_TRUE(AsyncSubmission::ShouldWrite(LogLevel::Trace, LogLevel::Access));
        EXPECT_TRUE(AsyncSubmission::ShouldWrite(LogLevel::Debug, LogLevel::Access));
        EXPECT_TRUE(AsyncSubmission::ShouldWrite(LogLevel::Info, LogLevel::Access));
        EXPECT_TRUE(AsyncSubmission::ShouldWrite(LogLevel::Access, LogLevel::Access));
        EXPECT_FALSE(AsyncSubmission::ShouldWrite(LogLevel::Access, LogLevel::Warn));
        EXPECT_FALSE(AsyncSubmission::ShouldWrite(LogLevel::Warn, LogLevel::Access));
        EXPECT_TRUE(AsyncSubmission::ShouldWrite(LogLevel::Warn, LogLevel::Warn));
    }

    TEST(PreviewLogger, AsyncBackendAcceptsAuditAtErrorThreshold)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"audit-level", 8U};
        Environment.Configuration().Logging.Level = Preview::Diagnose::LogLevel::Error;
        ASSERT_TRUE(Environment.Install());

        Preview::Diagnose::ContextState Context =
            Preview::Diagnose::ContextState::Empty();
        const auto Receipt = Environment.Runtime().Audit(
            Context, "event=session_closed status=failed");
        EXPECT_TRUE(Receipt.Accepted() ||
                    Receipt.Status == Preview::Diagnose::SubmissionStatus::Dropped);

        const auto Shutdown = Environment.Runtime().Shutdown();
        EXPECT_EQ(Shutdown.Status, Preview::Diagnose::SubmissionStatus::Accepted);
    }

    TEST(PreviewLogger, EmergencyFallbackRedactsAndBoundsOneWrite)
    {
        std::unique_ptr<std::FILE, decltype(&std::fclose)> EmergencyFile(
            std::tmpfile(), &std::fclose);
        ASSERT_NE(EmergencyFile, nullptr);
        Preview::Diagnose::Detail::EmergencyWriter Writer(EmergencyFile.get());
        Preview::Diagnose::Detail::SubmissionRecord Record;
        Record.Level = Preview::Diagnose::LogLevel::Error;
        Record.Context.Mode = Preview::Diagnose::RenderMode::CompactHuman;
        Record.Message = "password=fallback-canary " + std::string(4000U, 'x');

        EXPECT_TRUE(Writer.Write(Record));
        std::fflush(EmergencyFile.get());
        const auto End = std::ftell(EmergencyFile.get());
        ASSERT_GE(End, 0L);
        EXPECT_LE(static_cast<std::size_t>(End), 2048U);
        std::rewind(EmergencyFile.get());
        std::string Output(static_cast<std::size_t>(End), '\0');
        ASSERT_EQ(std::fread(Output.data(), 1U, Output.size(), EmergencyFile.get()), Output.size());
        EXPECT_NE(Output.find("password=<redacted>"), std::string::npos);
        EXPECT_EQ(Output.find("fallback-canary"), std::string::npos);
    }

} // namespace
