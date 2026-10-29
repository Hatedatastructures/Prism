/**
 * @file AsyncBackendInitTest.cpp
 * @brief Backend 初始化、幂等和配置冲突测试。
 */

#include <gtest/gtest.h>

#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <TestSupport/Prism/Diagnose/Environment.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace
{

    TEST(PrismLogger, InitializationRejectsDirectoryFailureAndConflictingConfig)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"initialize"};
        Environment.Configuration().Mode = Prism::Diagnose::RenderMode::Structured;
        const auto LogDirectory = Environment.Configuration().Logging.Directory;
        std::error_code DirectoryError;
        std::filesystem::create_directories(LogDirectory, DirectoryError);
        ASSERT_FALSE(DirectoryError);
        {
            std::ofstream Legacy(LogDirectory / "prism.log", std::ios::binary);
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
                  Prism::Application::DiagnoseRuntimeErrorCode::Directory);

        const auto Installed = Environment.Install();
        ASSERT_TRUE(Installed.has_value())
            << Installed.error().Message << " path=" << Installed.error().Path;
        const auto ArchiveTrigger = Environment.Runtime().Submit(
            Prism::Diagnose::LogLevel::Critical,
            Prism::Diagnose::ContextState::Empty(), "archive legacy log");
        ASSERT_EQ(ArchiveTrigger.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        const auto Drained = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
        ASSERT_EQ(Drained.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        const auto ArchivedPath = LogDirectory / "prism.log.legacy";
        ASSERT_TRUE(std::filesystem::exists(ArchivedPath));
        std::ifstream Archived(ArchivedPath, std::ios::binary);
        ASSERT_TRUE(Archived.is_open());
        const std::string ArchivedContents{std::istreambuf_iterator<char>{Archived},
                                            std::istreambuf_iterator<char>{}};
        EXPECT_NE(ArchivedContents.find("old_epoch"), std::string::npos);
        const auto CurrentPath = LogDirectory / "prism.log";
        std::ifstream Current(CurrentPath, std::ios::binary);
        ASSERT_TRUE(Current.is_open());
        const std::string CurrentContents{std::istreambuf_iterator<char>{Current},
                                          std::istreambuf_iterator<char>{}};
        EXPECT_NE(CurrentContents.find("archive legacy log"), std::string::npos);
        EXPECT_TRUE(Environment.Install().has_value());
        auto ConflictingConfiguration = Environment.Configuration();
        ++ConflictingConfiguration.Logging.QueueCapacity;
        const auto Conflict = Environment.Runtime().Install(ConflictingConfiguration);
        ASSERT_FALSE(Conflict.has_value());
        EXPECT_EQ(Conflict.error().Code,
                  Prism::Application::DiagnoseRuntimeErrorCode::ConfigurationConflict);

        const auto Shutdown = Environment.Runtime().Shutdown();
        EXPECT_EQ(Shutdown.Status, Prism::Diagnose::SubmissionStatus::Closed);
    }

} // namespace
