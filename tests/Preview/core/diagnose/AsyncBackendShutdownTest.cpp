/**
 * @file AsyncBackendShutdownTest.cpp
 * @brief Drain、重复 Shutdown 和 stopped receipt 测试。
 */

#include <gtest/gtest.h>

#include <TestSupport/Preview/DiagnoseTestEnvironment.hpp>

#include <chrono>
#include <string>

namespace
{

    TEST(PreviewLogger, BeginShutdownStopsSubmissionsAndControlThreadFinalizationJoins)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"shutdown", 128U};
        ASSERT_TRUE(Environment.Install().has_value());
        const auto Context = Preview::Diagnose::ContextState::Empty()
                                 .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{5});
        EXPECT_EQ(Environment.Runtime()
                      .Submit(Preview::Diagnose::LogLevel::Info, Context, "before shutdown")
                      .Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);

        Environment.Runtime().BeginShutdown();
        EXPECT_FALSE(Environment.Runtime().IsInstalled());
        EXPECT_EQ(Environment.Runtime().FinalizeShutdown().Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Environment.Runtime().FinalizeShutdown().Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(Environment.Runtime()
                      .Submit(Preview::Diagnose::LogLevel::Info, Context, "after shutdown")
                      .Status,
                  Preview::Diagnose::SubmissionStatus::Stopped);
        EXPECT_FALSE(Environment.Runtime().IsInstalled());
    }

} // namespace
