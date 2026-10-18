/**
 * @file ContextStateTest.cpp
 * @brief 不可变诊断上下文和 inline 容量契约测试。
 */

#include <gtest/gtest.h>

#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace
{

    using Prism::Diagnose::ContextError;
    using Prism::Diagnose::Fields::Correlation;
    using Prism::Diagnose::Fields::Generation;
    using Prism::Diagnose::Fields::Operation;
    using Prism::Diagnose::Fields::Process;
    using Prism::Diagnose::Fields::Route;
    using Prism::Diagnose::Fields::Session;
    using Prism::Diagnose::Fields::Task;
    using Prism::Diagnose::Fields::Worker;
    using Prism::Diagnose::ContextState;

    template <typename Value>
    concept CanTryWithRoute = requires(const ContextState &Context, Value &&Input)
    {
        Context.TryWith(Route, std::forward<Value>(Input));
    };

    static_assert(sizeof(ContextState) <= 128U);
    static_assert(CanTryWithRoute<std::string &>);
    static_assert(!CanTryWithRoute<std::string>);

    TEST(PrismDiagnose, ContextStateEmptyHasNoPrefix)
    {
        const auto Root = ContextState::Empty();

        EXPECT_TRUE(Root.CompactPrefix().empty());
        EXPECT_EQ(Root.FieldCount(), 0U);
    }

    TEST(PrismDiagnose, WorkerAndSessionDeriveCachedPrefixesWithoutChangingParents)
    {
        const auto Root = ContextState::Empty();
        const auto WorkerContext = Root.With(Worker, Prism::WorkerId{7});
        const auto SessionContext = WorkerContext.With(Session, Prism::SessionId{9});

        EXPECT_TRUE(Root.CompactPrefix().empty());
        EXPECT_EQ(WorkerContext.CompactPrefix(), "[W7]");
        EXPECT_EQ(SessionContext.CompactPrefix(), "[W7][S9]");
        EXPECT_EQ(WorkerContext.FieldCount(), 0U);
        EXPECT_EQ(SessionContext.FieldCount(), 0U);
    }

    TEST(PrismDiagnose, WithReplacesTheSameFieldInTheChildOnly)
    {
        const auto Root = ContextState::Empty();
        const auto Parent = Root.With(Route, std::string_view{"edge-a"});
        const auto Child = Parent.With(Route, std::string_view{"edge-b"});

        EXPECT_EQ(Root.FieldCount(), 0U);
        EXPECT_EQ(Parent.FieldCount(), 1U);
        EXPECT_EQ(Child.FieldCount(), 1U);
    }

    TEST(PrismDiagnose, PersistentWithUsesOwnedOverflowAndReservesPerCallSlots)
    {
        const auto Persistent = ContextState::Empty()
                                   .With(Worker, Prism::WorkerId{7})
                                   .With(Session, Prism::SessionId{9})
                                   .With(Correlation, Prism::RequestId{1})
                                   .With(Process, Prism::ProcessId{2})
                                   .With(Generation, Prism::GenerationId{3})
                                   .With(Task, Prism::TaskId{4})
                                   .With(Operation, Prism::OperationId{5});
        EXPECT_EQ(Persistent.FieldCount(), 5U);

        const std::string_view RouteValue{"route"};
        const std::string_view ProtocolValue{"vless"};
        const std::string_view SniValue{"edge.example"};
        const std::string_view AlpnValue{"h2"};
        const auto First = Persistent.TryWith(Route, RouteValue);
        ASSERT_TRUE(First.has_value());
        const auto Second = First->TryWith(Prism::Diagnose::Fields::Protocol, ProtocolValue);
        ASSERT_TRUE(Second.has_value());
        const auto Third = Second->TryWith(Prism::Diagnose::Fields::Stream,
                                           Prism::StreamId{6});
        ASSERT_TRUE(Third.has_value());
        const auto Fourth = Third->TryWith(Prism::Diagnose::Fields::Sni, SniValue);
        ASSERT_TRUE(Fourth.has_value());
        EXPECT_EQ(Fourth->FieldCount(), 9U);
        EXPECT_FALSE(Fourth->TryWith(Prism::Diagnose::Fields::Alpn,
                                     AlpnValue).has_value());
    }

    TEST(PrismDiagnose, TryWithRejectsTheFifthPerCallFieldWithoutTruncatingContext)
    {
        const auto Base = ContextState::Empty()
                              .With(Worker, Prism::WorkerId{7})
                              .With(Session, Prism::SessionId{9});
        const auto First = Base.TryWith(Correlation, Prism::RequestId{1});
        ASSERT_TRUE(First.has_value());
        const auto Second = First->TryWith(Process, Prism::ProcessId{2});
        ASSERT_TRUE(Second.has_value());
        const auto Third = Second->TryWith(Generation, Prism::GenerationId{3});
        ASSERT_TRUE(Third.has_value());
        const auto Fourth = Third->TryWith(Task, Prism::TaskId{4});
        ASSERT_TRUE(Fourth.has_value());

        const auto Overflow = Fourth->TryWith(Operation, Prism::OperationId{5});

        ASSERT_FALSE(Overflow.has_value());
        EXPECT_EQ(Overflow.error(), ContextError::ContextCapacityExceeded);
        EXPECT_EQ(Fourth->FieldCount(), 4U);
        EXPECT_EQ(Fourth->CompactPrefix(), "[W7][S9]");
        EXPECT_EQ(Base.FieldCount(), 0U);
    }

} // namespace
