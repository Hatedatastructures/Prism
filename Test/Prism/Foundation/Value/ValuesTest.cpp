#include <gtest/gtest.h>

#include <type_traits>

#include <Prism/Foundation/Foundation.hpp>

namespace
{

    TEST(PrismTask2Identifiers, KeepDifferentIdKindsDistinct)
    {
        const auto Builtin = Prism::BuiltinId{7};
        const auto Snapshot = Prism::SnapshotId{7};
        const auto BuiltinSnapshot = Prism::BuiltinSnapshotId{7};
        const auto Generation = Prism::GenerationId{7};
        const auto Task = Prism::TaskId{7};
        const auto Session = Prism::SessionId{7};
        const auto Stream = Prism::StreamId{7};
        const auto Worker = Prism::WorkerId{7};
        const auto Kind = Prism::KindId::From("transport");
        const auto Name = Prism::NameId::From("tls");

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
        EXPECT_NE(Kind, Prism::KindId::From("protocol"));
        static_assert(!std::is_convertible_v<Prism::BuiltinId, Prism::SnapshotId>);
        static_assert(!std::is_same_v<Prism::BuiltinSnapshotId, Prism::SnapshotId>);
        static_assert(!std::is_convertible_v<Prism::BuiltinSnapshotId, Prism::SnapshotId>);
        static_assert(!std::is_convertible_v<Prism::SnapshotId, Prism::BuiltinSnapshotId>);
        static_assert(!std::is_convertible_v<Prism::TaskId, Prism::SessionId>);
        static_assert(!std::is_convertible_v<Prism::KindId, Prism::NameId>);
    }

    TEST(PrismTask2Error, ExpectedCarriesTypedError)
    {
        Prism::Foundation::Expected<int> Success = 42;
        Prism::Foundation::Expected<int> Failure =
            std::unexpected(Prism::Foundation::Error::InvalidArgument);

        ASSERT_TRUE(Success);
        EXPECT_EQ(*Success, 42);
        ASSERT_FALSE(Failure);
        EXPECT_EQ(Failure.error(), Prism::Foundation::Error::InvalidArgument);
    }

    TEST(PrismTask2FoundationValues, ExposeTypedExecutionValues)
    {
        EXPECT_EQ(Prism::Memory::Domain::Session, Prism::Memory::Domain::Session);
        EXPECT_EQ(Prism::Executor::Affinity::Worker, Prism::Executor::Affinity::Worker);
        EXPECT_EQ(Prism::Cancellation::Mode::Cooperative,
                  Prism::Cancellation::Mode::Cooperative);
    }

    TEST(PrismTask2FoundationValues, AggregateIncludesNewFoundationTypes)
    {
        Prism::Foundation::Status Status{};
        EXPECT_TRUE(Status.has_value());

        Prism::Memory::SessionResource<> Resource;
        EXPECT_NE(Resource.Arena(), nullptr);
        EXPECT_EQ(Prism::Executor::Affinity::Control, Prism::Executor::Affinity::Control);
        EXPECT_EQ(Prism::Cancellation::Mode::Required, Prism::Cancellation::Mode::Required);
    }

} // namespace
