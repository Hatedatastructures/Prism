/**
 * @file BackendRotationTest.cpp
 * @brief 单一 backend owner 的文件轮转测试。
 */

#include <gtest/gtest.h>

#include <TestSupport/Prism/Diagnose/Environment.hpp>

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
        std::uint64_t LastSequence = 0U;
        const std::string Payload(512U, 'x');
        for (std::size_t Index = 0; Index < 40U; ++Index)
        {
            const auto Receipt = Environment.Runtime().Submit(
                Prism::Diagnose::LogLevel::Info, Context,
                "Rotation Index=" + std::to_string(Index) + " " + Payload);
            ASSERT_EQ(Receipt.Status, Prism::Diagnose::SubmissionStatus::Accepted);
            LastSequence = Receipt.Sequence;
        }
        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{5});
        ASSERT_EQ(Flushed.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_FALSE(Flushed.Accepted());
        EXPECT_EQ(Flushed.Sequence, LastSequence);
        const auto Closed = Environment.Runtime().Shutdown();
        EXPECT_EQ(Closed.Status, Prism::Diagnose::SubmissionStatus::Closed);
        EXPECT_FALSE(Closed.Accepted());
        EXPECT_EQ(Closed.Sequence, LastSequence);
        EXPECT_TRUE(std::filesystem::exists(Configuration.Logging.Directory /
                                             Configuration.Logging.FileName));
        EXPECT_TRUE(std::filesystem::exists(Configuration.Logging.Directory /
                                             "prism.1.log"));
    }

} // namespace
