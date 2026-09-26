/**
 * @file AsyncBackendInitializationTest.cpp
 * @brief Backend 初始化、幂等和配置冲突测试。
 */

#include <gtest/gtest.h>

#include <TestSupport/Preview/DiagnoseTestEnvironment.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace
{

    TEST(PreviewLogger, InitializationRejectsDirectoryFailureAndConflictingConfig)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"initialize"};
        Environment.Configuration().Mode = Preview::Diagnose::RenderMode::Structured;
        const auto LogDirectory = Environment.Configuration().Logging.Directory;
        std::error_code DirectoryError;
        std::filesystem::create_directories(LogDirectory, DirectoryError);
        ASSERT_FALSE(DirectoryError);
        {
            std::ofstream Legacy(LogDirectory / "preview.log", std::ios::binary);
            ASSERT_TRUE(Legacy.is_open());
            Legacy << "1710000000 [info] event=old_epoch message=legacy\n";
        }

        const auto BlockingPath = Environment.Root() / "blocked-directory";
        {
            std::ofstream BlockingFile(BlockingPath, std::ios::binary);
            ASSERT_TRUE(BlockingFile.is_open());
            BlockingFile << "block";
        }

        auto InvalidConfiguration = Environment.Configuration();
        InvalidConfiguration.Logging.Directory = BlockingPath;
        const auto Invalid = Environment.Runtime().Install(InvalidConfiguration);
        ASSERT_FALSE(Invalid.has_value());
        EXPECT_EQ(Invalid.error().Code,
                  Preview::Application::DiagnoseRuntimeErrorCode::Directory);

        const auto Installed = Environment.Install();
        ASSERT_TRUE(Installed.has_value())
            << Installed.error().Message << " path=" << Installed.error().Path;
        const auto ArchivedPath = LogDirectory / "preview.log.legacy";
        ASSERT_TRUE(std::filesystem::exists(ArchivedPath));
        std::ifstream Archived(ArchivedPath, std::ios::binary);
        ASSERT_TRUE(Archived.is_open());
        const std::string ArchivedContents{std::istreambuf_iterator<char>{Archived},
                                            std::istreambuf_iterator<char>{}};
        EXPECT_NE(ArchivedContents.find("old_epoch"), std::string::npos);
        EXPECT_TRUE(Environment.Install().has_value());
        auto ConflictingConfiguration = Environment.Configuration();
        ++ConflictingConfiguration.Logging.QueueCapacity;
        const auto Conflict = Environment.Runtime().Install(ConflictingConfiguration);
        ASSERT_FALSE(Conflict.has_value());
        EXPECT_EQ(Conflict.error().Code,
                  Preview::Application::DiagnoseRuntimeErrorCode::ConfigurationConflict);

        const auto Shutdown = Environment.Runtime().Shutdown();
        EXPECT_EQ(Shutdown.Status, Preview::Diagnose::SubmissionStatus::Accepted);
    }

} // namespace
