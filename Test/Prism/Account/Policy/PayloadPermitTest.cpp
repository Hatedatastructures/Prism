/** @file PayloadPermitTest.cpp @brief 授权移动、完成和保守结算契约。 */
#include <Prism/Contract/Account/PayloadBudget.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <utility>

namespace
{

    class RecordingPayloadLedger final : public Prism::Contract::PayloadSettlement
    {
    public:
        auto Complete(const std::uint64_t Granted, const std::uint64_t Transferred) noexcept
            -> void override
        {
            ++CompleteCalls;
            LastGranted = Granted;
            LastTransferred = Transferred;
            TotalGrantedBytes += Granted;
            CommittedBytes += Transferred;
            if (Transferred > Granted)
            {
                ExceededGrant = true;
                return;
            }
            RefundedBytes += Granted - Transferred;
        }

        std::uint32_t CompleteCalls{0U};
        std::uint64_t LastGranted{0U};
        std::uint64_t LastTransferred{0U};
        std::uint64_t TotalGrantedBytes{0U};
        std::uint64_t CommittedBytes{0U};
        std::uint64_t RefundedBytes{0U};
        bool ExceededGrant{false};
    };

} // namespace

TEST(PrismPayloadPermit, MoveAssignmentSettlesDisplacedReservationBeforeTakingSource)
{
    using Prism::Contract::PayloadPermit;

    const auto DisplacedLedger = std::make_shared<RecordingPayloadLedger>();
    const auto IncomingLedger = std::make_shared<RecordingPayloadLedger>();
    {
        PayloadPermit Destination{9U, DisplacedLedger};
        PayloadPermit Source{13U, IncomingLedger};

        Destination = std::move(Source);

        ASSERT_EQ(DisplacedLedger->CompleteCalls, 1U);
        EXPECT_EQ(DisplacedLedger->TotalGrantedBytes, 9U);
        EXPECT_EQ(DisplacedLedger->CommittedBytes, 0U);
        EXPECT_EQ(DisplacedLedger->RefundedBytes, 9U);
        EXPECT_EQ(Destination.Bytes(), 13U);
        EXPECT_EQ(Source.Bytes(), 0U);
    }

    EXPECT_EQ(DisplacedLedger->CompleteCalls, 1U);
    EXPECT_EQ(IncomingLedger->CompleteCalls, 1U);
    EXPECT_EQ(IncomingLedger->TotalGrantedBytes, 13U);
    EXPECT_EQ(IncomingLedger->CommittedBytes, 0U);
    EXPECT_EQ(IncomingLedger->RefundedBytes, 13U);
}

TEST(PrismPayloadPermit, ExplicitFinishIsNotRepeatedByDestruction)
{
    using Prism::Contract::PayloadPermit;

    const auto Ledger = std::make_shared<RecordingPayloadLedger>();
    {
        PayloadPermit Permit{8U, Ledger};
        Permit.Finish(3U);
        EXPECT_EQ(Permit.Bytes(), 0U);
        EXPECT_EQ(Ledger->CompleteCalls, 1U);
        EXPECT_EQ(Ledger->CommittedBytes, 3U);
        EXPECT_EQ(Ledger->RefundedBytes, 5U);
    }

    EXPECT_EQ(Ledger->CompleteCalls, 1U);
    EXPECT_EQ(Ledger->TotalGrantedBytes, 8U);
    EXPECT_EQ(Ledger->CommittedBytes, 3U);
    EXPECT_EQ(Ledger->RefundedBytes, 5U);
}

TEST(PrismPayloadPermit, ClampsTransferredBytesToGrantBeforeLedgerUpdate)
{
    using Prism::Contract::PayloadPermit;

    const auto Ledger = std::make_shared<RecordingPayloadLedger>();
    {
        PayloadPermit Permit{5U, Ledger};
        Permit.Finish(8U);
    }

    EXPECT_EQ(Ledger->CompleteCalls, 1U);
    EXPECT_EQ(Ledger->LastGranted, 5U);
    EXPECT_EQ(Ledger->LastTransferred, 5U);
    EXPECT_EQ(Ledger->TotalGrantedBytes, 5U);
    EXPECT_EQ(Ledger->CommittedBytes, 5U);
    EXPECT_EQ(Ledger->RefundedBytes, 0U);
    EXPECT_FALSE(Ledger->ExceededGrant);
}

TEST(PrismPayloadPermit, UnmeteredPermitFinishesWithoutSettlementOwner)
{
    Prism::Contract::PayloadPermit Permit{7U};

    EXPECT_EQ(Permit.Bytes(), 7U);
    Permit.Finish(4U);
    EXPECT_EQ(Permit.Bytes(), 0U);
    Permit.Finish(0U);
    EXPECT_EQ(Permit.Bytes(), 0U);
}
