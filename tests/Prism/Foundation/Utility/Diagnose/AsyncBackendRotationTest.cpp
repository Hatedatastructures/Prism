/**
 * @file AsyncBackendRotationTest.cpp
 * @brief 单一 backend owner 的文件轮转测试。
 */

#include <gtest/gtest.h>

#include <TestSupport/Prism/DiagnoseTestEnvironment.hpp>

#include <chrono>
#include <filesystem>
#include <string>

namespace
{

    TEST(PrismLogger, RotatesCurrentFormatFiles)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"rotation", 512U};
        auto &Configuration = Environment.Configuration();
        Configuration.Logging.RotateBytes = 4096U;
        ASSERT_TRUE(Environment.Install().has_value());

        const auto Context = Prism::Diagnose::ContextState::Empty()
                                 .With(Prism::Diagnose::Fields::Worker, Prism::WorkerId{2})
                                 .With(Prism::Diagnose::Fields::Session, Prism::SessionId{3});
        std::size_t Accepted = 0U;
        const std::string Payload(512U, 'x');
        for (std::size_t Index = 0; Index < 40U; ++Index)
        {
            const auto Receipt = Environment.Runtime().Submit(
                Prism::Diagnose::LogLevel::Info, Context,
                "Rotation Index=" + std::to_string(Index) + " " + Payload);
            if (Receipt.Status == Prism::Diagnose::SubmissionStatus::Accepted)
            {
                ++Accepted;
            }
        }
        ASSERT_GE(Accepted, 12U);
        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{5});
        EXPECT_EQ(Flushed.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_FALSE(Flushed.Accepted());
        const auto Closed = Environment.Runtime().Shutdown();
        EXPECT_EQ(Closed.Status, Prism::Diagnose::SubmissionStatus::Closed);
        EXPECT_FALSE(Closed.Accepted());
        EXPECT_TRUE(std::filesystem::exists(Configuration.Logging.Directory /
                                             Configuration.Logging.FileName));
        EXPECT_TRUE(std::filesystem::exists(Configuration.Logging.Directory /
                                             "prism.1.log"));
    }

} // namespace
