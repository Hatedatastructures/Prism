/** @file CommandJournalTest.cpp @brief 管理命令持久受理、重放与终态恢复合同。 */
#include "StorageTestSupport.hpp"

#include <Prism/Application/Storage/CommandJournal.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::StorageTests
{
    class CommandJournalStorage : public StorageFixture
    {
    };

    auto MakeCommandClaim(std::string Suffix, std::string Incarnation)
        -> Application::Storage::CommandClaim
    {
        return {"request-" + Suffix, "payload-" + Suffix, "operation-" + Suffix,
            std::move(Incarnation), "target-" + Suffix, 100};
    }

    TEST_F(CommandJournalStorage, ClaimReadsByBothKeysAndMissingRowsReturnEof)
    {
        Open();
        Application::Storage::CommandJournal Journal(Owner);
        const auto Claim = MakeCommandClaim("read", Owner->Incarnation());
        const auto Accepted = Run(Journal.Claim(Claim));
        ASSERT_TRUE(Accepted);
        EXPECT_TRUE(Accepted->Execute);
        EXPECT_EQ(Accepted->State, "accepted");
        EXPECT_EQ(Accepted->AcceptedAt, Claim.Timestamp);
        EXPECT_EQ(Accepted->Incarnation, Owner->Incarnation());

        const auto ByRequest = Run(Journal.Read({Claim.RequestKey, {}}));
        ASSERT_TRUE(ByRequest);
        EXPECT_FALSE(ByRequest->Execute);
        EXPECT_EQ(ByRequest->OperationId, Claim.OperationId);
        EXPECT_EQ(ByRequest->Payload, Claim.Payload);

        const auto ByOperation = Run(Journal.Read({{}, Claim.OperationId}));
        ASSERT_TRUE(ByOperation);
        EXPECT_EQ(ByOperation->RequestKey, Claim.RequestKey);
        EXPECT_FALSE(ByOperation->CompletedAt);

        const auto Missing = Run(Journal.Read({"missing-request", {}}));
        ASSERT_FALSE(Missing);
        EXPECT_EQ(Missing.error().Code, Fault::Code::Eof);

        const auto Invalid = Run(Journal.Read({{}, {}}));
        ASSERT_FALSE(Invalid);
        EXPECT_EQ(Invalid.error().Code, Fault::Code::InvalidArgument);
    }

    TEST_F(CommandJournalStorage, ClaimReplayRejectsPayloadTargetAndStaleIncarnation)
    {
        Open();
        Application::Storage::CommandJournal Journal(Owner);
        const auto Claim = MakeCommandClaim("replay", Owner->Incarnation());
        const auto Accepted = Run(Journal.Claim(Claim));
        ASSERT_TRUE(Accepted);

        const auto Duplicate = Run(Journal.Claim(Claim));
        ASSERT_TRUE(Duplicate);
        EXPECT_FALSE(Duplicate->Execute);
        EXPECT_EQ(Duplicate->State, "accepted");
        const auto PersistedDuplicate = Run(Journal.Read({Claim.RequestKey, {}}));
        ASSERT_TRUE(PersistedDuplicate);
        EXPECT_EQ(PersistedDuplicate->State, "accepted");
        EXPECT_EQ(PersistedDuplicate->Result, "");

        auto PayloadConflict = Claim;
        PayloadConflict.Payload = "changed-payload";
        const auto PayloadReplay = Run(Journal.Claim(std::move(PayloadConflict)));
        ASSERT_FALSE(PayloadReplay);
        EXPECT_EQ(PayloadReplay.error().Code, Fault::Code::ReplayDetected);

        auto TargetConflict = Claim;
        TargetConflict.Target = "changed-target";
        const auto TargetReplay = Run(Journal.Claim(std::move(TargetConflict)));
        ASSERT_FALSE(TargetReplay);
        EXPECT_EQ(TargetReplay.error().Code, Fault::Code::ReplayDetected);
        const auto PersistedConflict = Run(Journal.Read({Claim.RequestKey, {}}));
        ASSERT_TRUE(PersistedConflict);
        EXPECT_EQ(PersistedConflict->Payload, Claim.Payload);
        EXPECT_EQ(PersistedConflict->Target, Claim.Target);
        EXPECT_EQ(PersistedConflict->OperationId, Claim.OperationId);
        EXPECT_EQ(PersistedConflict->State, "accepted");
        EXPECT_EQ(PersistedConflict->Result, "");

        auto Stale = MakeCommandClaim("stale", "previous-incarnation");
        const auto StaleRequestKey = Stale.RequestKey;
        const auto StaleReplay = Run(Journal.Claim(std::move(Stale)));
        ASSERT_FALSE(StaleReplay);
        EXPECT_EQ(StaleReplay.error().Code, Fault::Code::ReplayDetected);
        const auto StaleRow = Run(Journal.Read({StaleRequestKey, {}}));
        ASSERT_FALSE(StaleRow);
        EXPECT_EQ(StaleRow.error().Code, Fault::Code::Eof);
    }

    TEST_F(CommandJournalStorage, EveryTerminalStateIsIdempotentAndImmutable)
    {
        Open();
        const auto OriginalIncarnation = Owner->Incarnation();
        constexpr std::array<std::string_view, 9> TerminalStates{
            "completed", "rejected", "unavailable", "failed", "timed_out",
            "blocked", "restart_required", "conflict", "invalid"};

        {
            Application::Storage::CommandJournal Journal(Owner);
            for (std::size_t Index = 0; Index < TerminalStates.size(); ++Index)
            {
                const auto Suffix = std::to_string(Index);
                const auto Claim = MakeCommandClaim(Suffix, Owner->Incarnation());
                const auto Accepted = Run(Journal.Claim(Claim));
                ASSERT_TRUE(Accepted);
                EXPECT_TRUE(Accepted->Execute);

                const auto Invalid = Run(Journal.Complete(
                    {Claim.OperationId, "accepted", "invalid-transition", 101}));
                ASSERT_FALSE(Invalid);
                EXPECT_EQ(Invalid.error().Code, Fault::Code::InvalidArgument);

                const std::string State(TerminalStates[Index]);
                const std::string Result = "result-" + Suffix;
                const auto Early = Run(Journal.Complete(
                    {Claim.OperationId, State, Result, Claim.Timestamp - 1}));
                ASSERT_FALSE(Early);
                EXPECT_EQ(Early.error().Code, Fault::Code::ReplayDetected);

                const auto Completed = Run(Journal.Complete(
                    {Claim.OperationId, State, Result, Claim.Timestamp}));
                ASSERT_TRUE(Completed);
                EXPECT_EQ(Completed->State, State);
                EXPECT_EQ(Completed->Result, Result);
                ASSERT_TRUE(Completed->CompletedAt);
                EXPECT_EQ(*Completed->CompletedAt, Claim.Timestamp);
                EXPECT_FALSE(Completed->Execute);

                const auto Duplicate = Run(Journal.Complete(
                    {Claim.OperationId, State, Result, Claim.Timestamp + 1}));
                ASSERT_TRUE(Duplicate);
                EXPECT_EQ(Duplicate->State, State);
                EXPECT_EQ(Duplicate->Result, Result);
                EXPECT_EQ(Duplicate->CompletedAt, Completed->CompletedAt);
                const auto PersistedDuplicate = Run(Journal.Read({{}, Claim.OperationId}));
                ASSERT_TRUE(PersistedDuplicate);
                EXPECT_EQ(PersistedDuplicate->State, State);
                EXPECT_EQ(PersistedDuplicate->Result, Result);
                EXPECT_EQ(PersistedDuplicate->CompletedAt, Completed->CompletedAt);

                const auto ChangedResult = Run(Journal.Complete(
                    {Claim.OperationId, State, "changed-result", Claim.Timestamp + 2}));
                ASSERT_FALSE(ChangedResult);
                EXPECT_EQ(ChangedResult.error().Code, Fault::Code::ReplayDetected);
                const auto AfterChangedResult = Run(Journal.Read({{}, Claim.OperationId}));
                ASSERT_TRUE(AfterChangedResult);
                EXPECT_EQ(AfterChangedResult->State, State);
                EXPECT_EQ(AfterChangedResult->Result, Result);

                const std::string OtherTerminal = State == "completed" ? "failed" : "completed";
                const auto ChangedTerminal = Run(Journal.Complete(
                    {Claim.OperationId, OtherTerminal, Result, Claim.Timestamp + 2}));
                ASSERT_FALSE(ChangedTerminal);
                EXPECT_EQ(ChangedTerminal.error().Code, Fault::Code::ReplayDetected);

                const auto PersistedConflict = Run(Journal.Read({{}, Claim.OperationId}));
                ASSERT_TRUE(PersistedConflict);
                EXPECT_EQ(PersistedConflict->State, State);
                EXPECT_EQ(PersistedConflict->Result, Result);
                EXPECT_EQ(PersistedConflict->CompletedAt, Completed->CompletedAt);
            }
        }

        Close();
        Open("incarnation-after-terminal-restart");
        Application::Storage::CommandJournal RestartedJournal(Owner);
        for (std::size_t Index = 0; Index < TerminalStates.size(); ++Index)
        {
            const auto Suffix = std::to_string(Index);
            const std::string State(TerminalStates[Index]);
            const auto Persisted = Run(RestartedJournal.Read({{}, "operation-" + Suffix}));
            ASSERT_TRUE(Persisted);
            EXPECT_EQ(Persisted->State, State);
            EXPECT_EQ(Persisted->Result, "result-" + Suffix);
            ASSERT_TRUE(Persisted->CompletedAt);
            EXPECT_EQ(*Persisted->CompletedAt, 100);
            EXPECT_EQ(Persisted->Incarnation, OriginalIncarnation);
            EXPECT_FALSE(Persisted->Execute);
        }
    }

    TEST_F(CommandJournalStorage, RestartMarksAcceptedCommandInterruptedWithoutReexecution)
    {
        Open("incarnation-before-restart");
        const auto Claim = MakeCommandClaim("restart", Owner->Incarnation());
        {
            Application::Storage::CommandJournal Journal(Owner);
            const auto Accepted = Run(Journal.Claim(Claim));
            ASSERT_TRUE(Accepted);
            EXPECT_TRUE(Accepted->Execute);
        }

        Close();
        Open("incarnation-after-restart");
        Application::Storage::CommandJournal Journal(Owner);
        const auto Persisted = Run(Journal.Read({Claim.RequestKey, {}}));
        ASSERT_TRUE(Persisted);
        EXPECT_EQ(Persisted->State, "interrupted");
        EXPECT_EQ(Persisted->Result, "process_restarted");
        EXPECT_EQ(Persisted->Incarnation, "incarnation-before-restart");
        EXPECT_FALSE(Persisted->Execute);

        auto Retry = Claim;
        Retry.ExpectedIncarnation = Owner->Incarnation();
        const auto Duplicate = Run(Journal.Claim(std::move(Retry)));
        ASSERT_TRUE(Duplicate);
        EXPECT_FALSE(Duplicate->Execute);
        EXPECT_EQ(Duplicate->State, "interrupted");

        const auto Completion = Run(Journal.Complete(
            {Claim.OperationId, "completed", "late-result", Claim.Timestamp + 1}));
        ASSERT_FALSE(Completion);
        EXPECT_EQ(Completion.error().Code, Fault::Code::ReplayDetected);
    }
}
