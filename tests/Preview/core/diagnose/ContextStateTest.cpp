/**
 * @file ContextStateTest.cpp
 * @brief 不可变诊断上下文和 inline 容量契约测试。
 */

#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace
{

    using Preview::Diagnose::ContextError;
    using Preview::Diagnose::Fields::Correlation;
    using Preview::Diagnose::Fields::Generation;
    using Preview::Diagnose::Fields::Operation;
    using Preview::Diagnose::Fields::Process;
    using Preview::Diagnose::Fields::Route;
    using Preview::Diagnose::Fields::Session;
    using Preview::Diagnose::Fields::Task;
    using Preview::Diagnose::Fields::Worker;
    using Preview::Diagnose::ContextState;

    template <typename Value>
    concept CanTryWithRoute = requires(const ContextState &Context, Value &&Input)
    {
        Context.TryWith(Route, std::forward<Value>(Input));
    };

    static_assert(sizeof(ContextState) <= 128U);
    static_assert(CanTryWithRoute<std::string &>);
    static_assert(!CanTryWithRoute<std::string>);

    TEST(PreviewDiagnose, ContextStateEmptyHasNoPrefix)
    {
        const auto Root = ContextState::Empty();

        EXPECT_TRUE(Root.CompactPrefix().empty());
        EXPECT_EQ(Root.FieldCount(), 0U);
    }

    TEST(PreviewDiagnose, WorkerAndSessionDeriveCachedPrefixesWithoutChangingParents)
    {
        const auto Root = ContextState::Empty();
        const auto WorkerContext = Root.With(Worker, Preview::WorkerId{7});
        const auto SessionContext = WorkerContext.With(Session, Preview::SessionId{9});

        EXPECT_TRUE(Root.CompactPrefix().empty());
        EXPECT_EQ(WorkerContext.CompactPrefix(), "[W7]");
        EXPECT_EQ(SessionContext.CompactPrefix(), "[W7][S9]");
        EXPECT_EQ(WorkerContext.FieldCount(), 0U);
        EXPECT_EQ(SessionContext.FieldCount(), 0U);
    }

    TEST(PreviewDiagnose, WithReplacesTheSameFieldInTheChildOnly)
    {
        const auto Root = ContextState::Empty();
        const auto Parent = Root.With(Route, std::string_view{"edge-a"});
        const auto Child = Parent.With(Route, std::string_view{"edge-b"});

        EXPECT_EQ(Root.FieldCount(), 0U);
        EXPECT_EQ(Parent.FieldCount(), 1U);
        EXPECT_EQ(Child.FieldCount(), 1U);
    }

    TEST(PreviewDiagnose, PersistentWithUsesOwnedOverflowAndReservesPerCallSlots)
    {
        const auto Persistent = ContextState::Empty()
                                   .With(Worker, Preview::WorkerId{7})
                                   .With(Session, Preview::SessionId{9})
                                   .With(Correlation, Preview::RequestId{1})
                                   .With(Process, Preview::ProcessId{2})
                                   .With(Generation, Preview::GenerationId{3})
                                   .With(Task, Preview::TaskId{4})
                                   .With(Operation, Preview::OperationId{5});
        EXPECT_EQ(Persistent.FieldCount(), 5U);

        const std::string_view RouteValue{"route"};
        const std::string_view ProtocolValue{"vless"};
        const std::string_view SniValue{"edge.example"};
        const std::string_view AlpnValue{"h2"};
        const auto First = Persistent.TryWith(Route, RouteValue);
        ASSERT_TRUE(First.has_value());
        const auto Second = First->TryWith(Preview::Diagnose::Fields::Protocol, ProtocolValue);
        ASSERT_TRUE(Second.has_value());
        const auto Third = Second->TryWith(Preview::Diagnose::Fields::Stream,
                                           Preview::StreamId{6});
        ASSERT_TRUE(Third.has_value());
        const auto Fourth = Third->TryWith(Preview::Diagnose::Fields::Sni, SniValue);
        ASSERT_TRUE(Fourth.has_value());
        EXPECT_EQ(Fourth->FieldCount(), 9U);
        EXPECT_FALSE(Fourth->TryWith(Preview::Diagnose::Fields::Alpn,
                                     AlpnValue).has_value());
    }

    TEST(PreviewDiagnose, TryWithRejectsTheFifthPerCallFieldWithoutTruncatingContext)
    {
        const auto Base = ContextState::Empty()
                              .With(Worker, Preview::WorkerId{7})
                              .With(Session, Preview::SessionId{9});
        const auto First = Base.TryWith(Correlation, Preview::RequestId{1});
        ASSERT_TRUE(First.has_value());
        const auto Second = First->TryWith(Process, Preview::ProcessId{2});
        ASSERT_TRUE(Second.has_value());
        const auto Third = Second->TryWith(Generation, Preview::GenerationId{3});
        ASSERT_TRUE(Third.has_value());
        const auto Fourth = Third->TryWith(Task, Preview::TaskId{4});
        ASSERT_TRUE(Fourth.has_value());

        const auto Overflow = Fourth->TryWith(Operation, Preview::OperationId{5});

        ASSERT_FALSE(Overflow.has_value());
        EXPECT_EQ(Overflow.error(), ContextError::ContextCapacityExceeded);
        EXPECT_EQ(Fourth->FieldCount(), 4U);
        EXPECT_EQ(Fourth->CompactPrefix(), "[W7][S9]");
        EXPECT_EQ(Base.FieldCount(), 0U);
    }

} // namespace
