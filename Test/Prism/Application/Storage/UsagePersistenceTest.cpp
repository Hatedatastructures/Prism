/** @file UsagePersistenceTest.cpp @brief 真实 SQLite 账本的预约、幂等、崩溃恢复和精确余额行为。 */
#include "StorageTestSupport.hpp"
#include <Prism/Application/Storage/Sqlite/Detail/Usage.hpp>
#include <limits>

namespace Prism::StorageTests
{
    class UsageStorage : public StorageFixture
    {
    public:
        auto Request(std::string Key, std::uint64_t Bytes = 1024U * 1024U) -> Account::UsageReservationRequest
        { return {Read, std::move(Key), Bytes, 2U * 1024U * 1024U}; }
        Account::UsageReadRequest Read{"account/northstar", {0, 1000}, 4U * 1024U * 1024U};
    };
    TEST_F(UsageStorage, DurableReservationAndPartialSettlementDoNotDoubleDeduct)
    {
        Open();
        Application::Storage::SqliteUsagePersistence Usage(Owner);
        auto Reservation = Run(Usage.Reserve(Request("reserve-1")));
        ASSERT_TRUE(Reservation);
        auto Snapshot = Run(Usage.Read(Read));
        ASSERT_TRUE(Snapshot);
        EXPECT_EQ(Snapshot->ReservedBytes, 1024U * 1024U);
        EXPECT_EQ(Snapshot->RemainingBytes, 3U * 1024U * 1024U);
        auto Partial = Run(Usage.Settle({Reservation->ReservationId, 100, false}));
        ASSERT_TRUE(Partial);
        EXPECT_EQ(Partial->SettledBytes, 100);
        EXPECT_EQ(Partial->ReservedBytes, 1024U * 1024U - 100);
        EXPECT_EQ(Partial->RemainingBytes, Snapshot->RemainingBytes);
        auto Final = Run(Usage.Settle({Reservation->ReservationId, 123, true}));
        ASSERT_TRUE(Final);
        EXPECT_EQ(Final->ReservedBytes, 0);
        EXPECT_EQ(Final->SettledBytes, 123);
        EXPECT_EQ(Final->RemainingBytes, 4U * 1024U * 1024U - 123);
        auto Duplicate = Run(Usage.Settle({Reservation->ReservationId, 123, true}));
        ASSERT_TRUE(Duplicate);
        EXPECT_EQ(Duplicate->Revision, Final->Revision);
        EXPECT_FALSE(Run(Usage.Settle({Reservation->ReservationId, 124, true})));
        EXPECT_FALSE(Run(Usage.Settle({Reservation->ReservationId, 123, false})));
    }
    TEST_F(UsageStorage, SameRequestIsIdempotentAndDifferentBodyConflicts)
    {
        Open();
        Application::Storage::SqliteUsagePersistence Usage(Owner);
        auto First = Run(Usage.Reserve(Request("same-key")));
        auto Again = Run(Usage.Reserve(Request("same-key")));
        ASSERT_TRUE(First); ASSERT_TRUE(Again);
        EXPECT_EQ(First->ReservationId, Again->ReservationId);
        EXPECT_EQ(First->Revision, Again->Revision);
        EXPECT_FALSE(Run(Usage.Reserve(Request("same-key", 42))));
        auto State = Run(Usage.Read(Read));
        ASSERT_TRUE(State);
        EXPECT_EQ(State->ReservedBytes, First->Bytes);
    }
    TEST_F(UsageStorage, OutstandingCapIsSharedAndFinalReleaseMakesCreditReusable)
    {
        Open();
        Application::Storage::SqliteUsagePersistence First(Owner);
        Application::Storage::SqliteUsagePersistence Second(Owner);
        auto One = Run(First.Reserve(Request("one")));
        auto Two = Run(Second.Reserve(Request("two")));
        ASSERT_TRUE(One); ASSERT_TRUE(Two);
        EXPECT_FALSE(Run(First.Reserve(Request("three"))));
        ASSERT_TRUE(Run(First.Settle({One->ReservationId, 7, true})));
        EXPECT_TRUE(Run(Second.Reserve(Request("three"))));
    }
    TEST_F(UsageStorage, GrantsLastByteAndZeroAllowanceBlocks)
    {
        Open();
        Application::Storage::SqliteUsagePersistence Usage(Owner);
        Read.LimitBytes = 1;
        auto Grant = Run(Usage.Reserve(Request("last-byte")));
        ASSERT_TRUE(Grant);
        EXPECT_EQ(Grant->Bytes, 1);
        ASSERT_TRUE(Run(Usage.Settle({Grant->ReservationId, 1, true})));
        EXPECT_FALSE(Run(Usage.Reserve(Request("exhausted"))));
        Read.AccountKey = "empty"; Read.LimitBytes = 0;
        EXPECT_FALSE(Run(Usage.Reserve(Request("zero"))));
    }
    TEST_F(UsageStorage, RestartKeepsInstanceAndMovesOnlyUnsettledRemainderToUncertain)
    {
        Open();
        const auto Identity = Owner->InstanceKey();
        std::string ReservationId;
        {
            Application::Storage::SqliteUsagePersistence Usage(Owner);
            auto Reserved = Run(Usage.Reserve(Request("pending")));
            ASSERT_TRUE(Reserved); ReservationId = Reserved->ReservationId;
            ASSERT_TRUE(Run(Usage.Settle({ReservationId, 17, false})));
        }
        Close(); Open("test-second");
        EXPECT_EQ(Owner->InstanceKey(), Identity);
        EXPECT_EQ(Owner->Incarnation(), "test-second");
        Application::Storage::SqliteUsagePersistence Usage(Owner);
        auto State = Run(Usage.Read(Read));
        ASSERT_TRUE(State);
        EXPECT_EQ(State->SettledBytes, 17);
        EXPECT_EQ(State->ReservedBytes, 0);
        EXPECT_EQ(State->UncertainBytes, 1024U * 1024U - 17);
        EXPECT_EQ(State->RemainingBytes, 3U * 1024U * 1024U);
        EXPECT_FALSE(Run(Usage.Settle({ReservationId, 18, true})));
    }
    TEST_F(UsageStorage, AdjustmentChecksRevisionAndPayloadAndReplaysOriginalResult)
    {
        Open();
        Application::Storage::SqliteUsagePersistence Usage(Owner);
        Account::UsageAdjustmentRequest Request{Read, Account::UsageAdjustmentKind::AddAllowance,
            100, 0, "add-first", "support adjustment"};
        auto First = Run(Usage.Adjust(Request));
        ASSERT_TRUE(First);
        EXPECT_EQ(First->AdditionalBytes, 100);
        auto Duplicate = Run(Usage.Adjust(Request));
        ASSERT_TRUE(Duplicate);
        EXPECT_EQ(Duplicate->Revision, First->Revision);
        Request.Bytes = 101;
        EXPECT_FALSE(Run(Usage.Adjust(Request)));
        Request.RequestKey = "second";
        EXPECT_FALSE(Run(Usage.Adjust(Request)));
        Request.ExpectedRevision = First->Revision;
        EXPECT_TRUE(Run(Usage.Adjust(Request)));
    }
    TEST_F(UsageStorage, FullUnsignedAllowanceDoesNotLosePrecision)
    {
        Open();
        Application::Storage::SqliteUsagePersistence Usage(Owner);
        Read.LimitBytes = (std::numeric_limits<std::uint64_t>::max)();
        auto Reserved = Run(Usage.Reserve(Request("precise", 1)));
        ASSERT_TRUE(Reserved);
        auto State = Run(Usage.Read(Read));
        ASSERT_TRUE(State);
        EXPECT_EQ(State->RemainingBytes, (std::numeric_limits<std::uint64_t>::max)() - 1);
    }
    TEST_F(UsageStorage, DirectoryAllowsOnlyOneWriterAndFailureDoesNotRemoveData)
    {
        Open();
        const auto Identity = Owner->InstanceKey();
        auto Duplicate = Run(Application::Storage::StorageRuntime::Open({Directory, "other"}));
        EXPECT_FALSE(Duplicate);
        EXPECT_EQ(Owner->InstanceKey(), Identity);
        EXPECT_TRUE(std::filesystem::exists(Directory / "ledger.sqlite3"));
    }
}
