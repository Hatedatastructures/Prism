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
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

namespace
{

    [[nodiscard]] auto ReadFile(const std::filesystem::path &Path) -> std::string
    {
        std::ifstream Input(Path, std::ios::binary);
        return {std::istreambuf_iterator<char>{Input}, std::istreambuf_iterator<char>{}};
    }

    [[nodiscard]] auto HasSingleLine(const std::string_view Text) noexcept -> bool
    {
        const auto Break = Text.find('\n');
        return Break != std::string_view::npos && Break + 1U == Text.size();
    }

    [[nodiscard]] auto WaitForEpochClose(
        const std::shared_ptr<const Preview::Diagnose::Detail::RenderEpochCloseState> &CloseState)
        -> bool
    {
        const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        while (!CloseState->Closed.load(std::memory_order_acquire) &&
            std::chrono::steady_clock::now() < Deadline)
        {
            std::this_thread::yield();
        }
        return CloseState->Closed.load(std::memory_order_acquire) &&
            !CloseState->Failed.load(std::memory_order_acquire);
    }

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
            Context, "SessionClosed Status=Failed");
        EXPECT_TRUE(Receipt.Accepted() ||
                    Receipt.Status == Preview::Diagnose::SubmissionStatus::Dropped);

        const auto Shutdown = Environment.Runtime().Shutdown();
        EXPECT_EQ(Shutdown.Status, Preview::Diagnose::SubmissionStatus::Closed);
    }

    TEST(PreviewLogger, RetainedGenerationKeepsItsRenderModeAcrossHotEpochChange)
    {
        using Preview::Diagnose::LogLevel;
        using Preview::Diagnose::RenderMode;
        using Preview::Diagnose::SubmissionStatus;
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"render-epoch", 32U};
        Environment.Configuration().Mode = RenderMode::Structured;
        Environment.Configuration().TraceSelection.IncludeWorker = false;
        Environment.Configuration().Logging.RotateBytes = 4096U;
        Environment.Configuration().Logging.RotateFiles = 2U;
        ASSERT_TRUE(Environment.Install().has_value());

        auto OldEpoch = Environment.Runtime().CurrentEpoch();
        auto OldContext = Preview::Diagnose::ContextState::Empty()
            .WithRenderEpoch(OldEpoch)
            .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{41U});
        const auto OldClose = OldEpoch->CloseState();

        auto AbortedConfiguration = Environment.Configuration();
        AbortedConfiguration.Logging.Directory = Environment.Root() / "aborted" / "logs";
        AbortedConfiguration.Logging.FileName = "candidate.log";
        const auto AbortedPath = AbortedConfiguration.Logging.Directory /
            AbortedConfiguration.Logging.FileName;
        const auto AbortedDirectories = AbortedConfiguration.Logging.Directory;
        const auto AbortedParent = AbortedDirectories.parent_path();
        auto Aborted = Environment.Runtime().PrepareEpoch(AbortedConfiguration);
        ASSERT_TRUE(Aborted.has_value());
        auto AbortedEpoch = *Aborted;
        const auto AbortedClose = AbortedEpoch->CloseState();
        ASSERT_TRUE(std::filesystem::exists(AbortedPath));
        Aborted->reset();
        AbortedEpoch.reset();
        ASSERT_TRUE(WaitForEpochClose(AbortedClose));
        EXPECT_FALSE(std::filesystem::exists(AbortedPath));
        EXPECT_FALSE(std::filesystem::exists(AbortedDirectories));
        EXPECT_FALSE(std::filesystem::exists(AbortedParent));

        const auto OldFiltered = Environment.Runtime().Submit(
            LogLevel::Debug, OldContext, "old-debug-filtered");

        auto NewConfiguration = Environment.Configuration();
        NewConfiguration.Logging.Level = LogLevel::Debug;
        NewConfiguration.Logging.RotateBytes = 8192U;
        NewConfiguration.Mode = RenderMode::HumanWithFields;
        NewConfiguration.TraceSelection.IncludeWorker = true;
        auto Prepared = Environment.Runtime().PrepareEpoch(NewConfiguration);
        ASSERT_TRUE(Prepared.has_value()) << Prepared.error().Message;
        auto NewEpoch = *Prepared;
        Prepared->reset();
        const auto NewClose = NewEpoch->CloseState();
        auto NewContext = Preview::Diagnose::ContextState::Empty()
            .WithRenderEpoch(NewEpoch)
            .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{52U});
        ASSERT_TRUE(Environment.Runtime().PublishEpoch(NewEpoch));

        const auto OldBefore = Environment.Runtime().Submit(
            LogLevel::Info, OldContext, "old-structured-before " + std::string(3000U, 'o'));
        const auto NewDebug = Environment.Runtime().Submit(
            LogLevel::Debug, NewContext, "new-human-debug " + std::string(5000U, 'h'));
        const auto OldAfter = Environment.Runtime().Submit(
            LogLevel::Info, OldContext, "old-structured-after-one " + std::string(3000U, 'a'));
        const auto OldAfterRotation = Environment.Runtime().Submit(
            LogLevel::Info, OldContext, "old-structured-after-two " + std::string(3000U, 'b'));
        EXPECT_EQ(OldFiltered.Status, SubmissionStatus::Filtered);
        EXPECT_EQ(OldBefore.Status, SubmissionStatus::Accepted);
        EXPECT_EQ(NewDebug.Status, SubmissionStatus::Accepted);
        EXPECT_EQ(OldAfter.Status, SubmissionStatus::Accepted);
        EXPECT_EQ(OldAfterRotation.Status, SubmissionStatus::Accepted);
        EXPECT_FALSE(OldClose->Closed.load(std::memory_order_acquire));

        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
        ASSERT_EQ(Flushed.Status, SubmissionStatus::Flushed);
        const auto Directory = Environment.Configuration().Logging.Directory;
        const auto StructuredArchive = ReadFile(Directory / "preview.structured.1.log");
        const auto HumanFieldsArchive = ReadFile(Directory / "preview.human-fields.1.log");
        const auto StructuredRotation = ReadFile(Directory / "preview.1.log");
        const auto Current = ReadFile(Directory / "preview.log");
        ASSERT_FALSE(StructuredArchive.empty());
        ASSERT_FALSE(HumanFieldsArchive.empty());
        ASSERT_FALSE(StructuredRotation.empty());
        ASSERT_FALSE(Current.empty());
        EXPECT_TRUE(HasSingleLine(StructuredArchive));
        EXPECT_TRUE(HasSingleLine(HumanFieldsArchive));
        EXPECT_TRUE(HasSingleLine(StructuredRotation));
        EXPECT_TRUE(HasSingleLine(Current));
        EXPECT_EQ(StructuredArchive.front(), '{');
        EXPECT_NE(StructuredArchive.find("old-structured-before"), std::string::npos);
        EXPECT_EQ(StructuredArchive.find("new-human-debug"), std::string::npos);
        EXPECT_EQ(HumanFieldsArchive.front(), '[');
        EXPECT_NE(HumanFieldsArchive.find("new-human-debug"), std::string::npos);
        EXPECT_NE(HumanFieldsArchive.find("[Worker=52]"), std::string::npos);
        EXPECT_EQ(HumanFieldsArchive.find("old-structured"), std::string::npos);
        EXPECT_EQ(StructuredRotation.front(), '{');
        EXPECT_NE(StructuredRotation.find("old-structured-after-one"), std::string::npos);
        EXPECT_EQ(Current.front(), '{');
        EXPECT_NE(Current.find("old-structured-after-two"), std::string::npos);
        EXPECT_EQ(Current.find("new-human-debug"), std::string::npos);
        EXPECT_EQ(Environment.Runtime().Written(), 4U);

        OldContext = {};
        OldEpoch.reset();
        ASSERT_TRUE(WaitForEpochClose(OldClose));
        NewContext = {};
        NewEpoch.reset();
        EXPECT_FALSE(NewClose->Closed.load(std::memory_order_acquire));
        const auto Closed = Environment.Runtime().Shutdown();
        EXPECT_EQ(Closed.Status, SubmissionStatus::Closed);
        EXPECT_TRUE(WaitForEpochClose(NewClose));
        const auto LogPath = Directory / "preview.log";
        const auto RenamedPath = std::filesystem::path(LogPath.string() + ".closed");
        std::error_code RenameError;
        std::filesystem::rename(LogPath, RenamedPath, RenameError);
        EXPECT_FALSE(RenameError);
    }

    TEST(PreviewLogger, DistinctHumanRenderModesNeverShareAPhysicalFile)
    {
        using Preview::Diagnose::LogLevel;
        using Preview::Diagnose::RenderMode;
        using Preview::Diagnose::SubmissionStatus;
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"render-human-modes", 16U};
        Environment.Configuration().Mode = RenderMode::HumanWithFields;
        ASSERT_TRUE(Environment.Install().has_value());

        auto OldEpoch = Environment.Runtime().CurrentEpoch();
        auto OldContext = Preview::Diagnose::ContextState::Empty()
            .WithRenderEpoch(OldEpoch)
            .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{41U});
        const auto OldClose = OldEpoch->CloseState();
        auto CompactConfiguration = Environment.Configuration();
        CompactConfiguration.Mode = RenderMode::CompactHuman;
        CompactConfiguration.TraceSelection = {};
        auto CompactPrepared = Environment.Runtime().PrepareEpoch(CompactConfiguration);
        ASSERT_TRUE(CompactPrepared.has_value()) << CompactPrepared.error().Message;
        auto CompactEpoch = *CompactPrepared;
        CompactPrepared->reset();
        const auto CompactClose = CompactEpoch->CloseState();
        auto CompactContext = Preview::Diagnose::ContextState::Empty()
            .WithRenderEpoch(CompactEpoch)
            .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{52U});
        ASSERT_TRUE(Environment.Runtime().PublishEpoch(CompactEpoch));

        const auto OldBefore = Environment.Runtime().Submit(
            LogLevel::Info, OldContext, "old-fields-before-mode-change");
        const auto Compact = Environment.Runtime().Submit(
            LogLevel::Info, CompactContext, "new-compact-mode");
        const auto OldAfter = Environment.Runtime().Submit(
            LogLevel::Info, OldContext, "old-fields-after-mode-change");
        EXPECT_EQ(OldBefore.Status, SubmissionStatus::Accepted);
        EXPECT_EQ(Compact.Status, SubmissionStatus::Accepted);
        EXPECT_EQ(OldAfter.Status, SubmissionStatus::Accepted);

        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
        ASSERT_EQ(Flushed.Status, SubmissionStatus::Flushed);
        const auto Directory = Environment.Configuration().Logging.Directory;
        const auto FieldsArchive = ReadFile(Directory / "preview.human-fields.1.log");
        const auto CompactArchive = ReadFile(Directory / "preview.compact-human.1.log");
        const auto Current = ReadFile(Directory / "preview.log");
        ASSERT_FALSE(FieldsArchive.empty());
        ASSERT_FALSE(CompactArchive.empty());
        ASSERT_FALSE(Current.empty());
        EXPECT_TRUE(HasSingleLine(FieldsArchive));
        EXPECT_TRUE(HasSingleLine(CompactArchive));
        EXPECT_TRUE(HasSingleLine(Current));
        EXPECT_NE(FieldsArchive.find("old-fields-before-mode-change"), std::string::npos);
        EXPECT_NE(FieldsArchive.find("[Worker=41]"), std::string::npos);
        EXPECT_EQ(FieldsArchive.find("new-compact-mode"), std::string::npos);
        EXPECT_NE(CompactArchive.find("new-compact-mode"), std::string::npos);
        EXPECT_NE(CompactArchive.find("[W52]"), std::string::npos);
        EXPECT_EQ(CompactArchive.find("[Worker=52]"), std::string::npos);
        EXPECT_EQ(CompactArchive.find("old-fields"), std::string::npos);
        EXPECT_NE(Current.find("old-fields-after-mode-change"), std::string::npos);
        EXPECT_NE(Current.find("[Worker=41]"), std::string::npos);
        EXPECT_EQ(Environment.Runtime().Written(), 3U);

        OldContext = {};
        OldEpoch.reset();
        CompactContext = {};
        CompactEpoch.reset();
        ASSERT_TRUE(WaitForEpochClose(OldClose));
        ASSERT_TRUE(WaitForEpochClose(CompactClose));
        const auto Closed = Environment.Runtime().Shutdown();
        EXPECT_EQ(Closed.Status, SubmissionStatus::Closed);
        const auto LogPath = Directory / "preview.log";
        const auto RenamedPath = std::filesystem::path(LogPath.string() + ".closed");
        std::error_code RenameError;
        std::filesystem::rename(LogPath, RenamedPath, RenameError);
        EXPECT_FALSE(RenameError);
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
