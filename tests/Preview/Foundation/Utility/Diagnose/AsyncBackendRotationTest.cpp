/**
 * @file AsyncBackendRotationTest.cpp
 * @brief 单一 backend owner 的文件轮转测试。
 */

#include <gtest/gtest.h>

#include <TestSupport/Preview/DiagnoseTestEnvironment.hpp>

#include <chrono>
#include <filesystem>
#include <string>

namespace
{

    TEST(PreviewLogger, RotatesCurrentFormatFiles)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"rotation", 512U};
        auto &Configuration = Environment.Configuration();
        Configuration.Logging.RotateBytes = 4096U;
        ASSERT_TRUE(Environment.Install().has_value());

        const auto Context = Preview::Diagnose::ContextState::Empty()
                                 .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{2})
                                 .With(Preview::Diagnose::Fields::Session, Preview::SessionId{3});
        std::size_t Accepted = 0U;
        const std::string Payload(512U, 'x');
        for (std::size_t Index = 0; Index < 40U; ++Index)
        {
            const auto Receipt = Environment.Runtime().Submit(
                Preview::Diagnose::LogLevel::Info, Context,
                "Rotation Index=" + std::to_string(Index) + " " + Payload);
            if (Receipt.Status == Preview::Diagnose::SubmissionStatus::Accepted)
            {
                ++Accepted;
            }
        }
        ASSERT_GE(Accepted, 12U);
        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{5});
        EXPECT_EQ(Flushed.Status, Preview::Diagnose::SubmissionStatus::Flushed);
        EXPECT_FALSE(Flushed.Accepted());
        const auto Closed = Environment.Runtime().Shutdown();
        EXPECT_EQ(Closed.Status, Preview::Diagnose::SubmissionStatus::Closed);
        EXPECT_FALSE(Closed.Accepted());
        EXPECT_TRUE(std::filesystem::exists(Configuration.Logging.Directory /
                                             Configuration.Logging.FileName));
        EXPECT_TRUE(std::filesystem::exists(Configuration.Logging.Directory /
                                             "preview.1.log"));
    }

} // namespace
