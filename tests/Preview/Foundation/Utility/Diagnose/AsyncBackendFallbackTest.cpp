/**
 * @file AsyncBackendFallbackTest.cpp
 * @brief Emergency fallback 的脱敏和长度上限测试。
 */

#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp>

#include <cstdio>
#include <memory>
#include <string>

namespace
{

    TEST(PreviewLoggerFallback, EmergencyFallbackRedactsAndBoundsOneWrite)
    {
        std::unique_ptr<std::FILE, decltype(&std::fclose)> EmergencyFile(std::tmpfile(), &std::fclose);
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
