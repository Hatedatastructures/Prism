#include <gtest/gtest.h>

#include <type_traits>

#include <Preview/Foundation/Foundation.hpp>

namespace
{

    TEST(PreviewTask2Identifiers, KeepDifferentIdKindsDistinct)
    {
        const auto Builtin = Preview::BuiltinId{7};
        const auto Snapshot = Preview::SnapshotId{7};
        const auto BuiltinSnapshot = Preview::BuiltinSnapshotId{7};
        const auto Generation = Preview::GenerationId{7};
        const auto Task = Preview::TaskId{7};
        const auto Session = Preview::SessionId{7};
        const auto Stream = Preview::StreamId{7};
        const auto Worker = Preview::WorkerId{7};
        const auto Kind = Preview::KindId::From("transport");
        const auto Name = Preview::NameId::From("tls");

        EXPECT_EQ(Builtin.Value(), 7U);
        EXPECT_EQ(Snapshot.Value(), 7U);
        EXPECT_EQ(BuiltinSnapshot.Value(), 7U);
        EXPECT_EQ(Generation.Value(), 7U);
        EXPECT_EQ(Task.Value(), 7U);
        EXPECT_EQ(Session.Value(), 7U);
        EXPECT_EQ(Stream.Value(), 7U);
        EXPECT_EQ(Worker.Value(), 7U);
        EXPECT_EQ(Kind.Value(), "transport");
        EXPECT_EQ(Name.Value(), "tls");
        EXPECT_NE(Kind, Preview::KindId::From("protocol"));
        static_assert(!std::is_convertible_v<Preview::BuiltinId, Preview::SnapshotId>);
        static_assert(!std::is_same_v<Preview::BuiltinSnapshotId, Preview::SnapshotId>);
        static_assert(!std::is_convertible_v<Preview::BuiltinSnapshotId, Preview::SnapshotId>);
        static_assert(!std::is_convertible_v<Preview::SnapshotId, Preview::BuiltinSnapshotId>);
        static_assert(!std::is_convertible_v<Preview::TaskId, Preview::SessionId>);
        static_assert(!std::is_convertible_v<Preview::KindId, Preview::NameId>);
    }

    TEST(PreviewTask2Error, ExpectedCarriesTypedError)
    {
        Preview::Foundation::Expected<int> Success = 42;
        Preview::Foundation::Expected<int> Failure =
            std::unexpected(Preview::Foundation::Error::InvalidArgument);

        ASSERT_TRUE(Success);
        EXPECT_EQ(*Success, 42);
        ASSERT_FALSE(Failure);
        EXPECT_EQ(Failure.error(), Preview::Foundation::Error::InvalidArgument);
    }

    TEST(PreviewTask2FoundationValues, ExposeTypedExecutionValues)
    {
        EXPECT_EQ(Preview::Memory::Domain::Session, Preview::Memory::Domain::Session);
        EXPECT_EQ(Preview::Executor::Affinity::Worker, Preview::Executor::Affinity::Worker);
        EXPECT_EQ(Preview::Cancellation::Mode::Cooperative,
                  Preview::Cancellation::Mode::Cooperative);
    }

    TEST(PreviewTask2FoundationValues, AggregateIncludesNewFoundationTypes)
    {
        Preview::Foundation::Status Status{};
        EXPECT_TRUE(Status.has_value());

        Preview::Memory::SessionResource<> Resource;
        EXPECT_NE(Resource.Arena(), nullptr);
        EXPECT_EQ(Preview::Executor::Affinity::Control, Preview::Executor::Affinity::Control);
        EXPECT_EQ(Preview::Cancellation::Mode::Required, Preview::Cancellation::Mode::Required);
    }

} // namespace
