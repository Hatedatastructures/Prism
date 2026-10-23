/**
 * @file CancelOnlyTest.cpp
 * @brief 验证取消只中断活动操作，最终 Close/Drain 仍拥有物理退休。
 */

#include "CanceledRetireTestSupport.hpp"

#include <gtest/gtest.h>

TEST(ActiveTransportsCanceledRetirement, KeepsExplicitCancellationIntentThroughFinalize)
{
    auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    auto State = std::make_shared<CanceledRetirementState>();
    auto Datagram = std::make_shared<CanceledDrainDatagram>(
        Context->Io.get_executor(), State);
    std::weak_ptr<CanceledDrainDatagram> WeakDatagram = Datagram;
    const auto Activity = Datagram->Activity();
    const auto Domain = Prism::Runtime::CarrierDomain::Create(
        Context->Io.get_executor(), Activity);
    ASSERT_TRUE(Domain);

    Prism::Runtime::ActiveTransports Active;
    auto Stored = Active.StoreDatagram(Datagram, *Domain);
    ASSERT_TRUE(Stored);
    auto HeldViews = Active.Load();
    ASSERT_TRUE(HeldViews.Datagram);
    Stored->reset();
    Datagram.reset();
    Active.MarkCancelRequested();

    EXPECT_EQ(State->CancelCalls.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_relaxed), 0U);
    Context->Io.run();

    EXPECT_EQ(State->CancelCalls.load(std::memory_order_relaxed), 1U);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(State->DrainCalls.load(std::memory_order_relaxed), 0U);
    EXPECT_FALSE(State->PhysicallyRetired.load(std::memory_order_acquire));
    EXPECT_FALSE(Activity->IsRetired());
    EXPECT_GT(Storage->Pending(), 0U);
    EXPECT_FALSE(WeakDatagram.expired());
    EXPECT_TRUE(HeldViews.Datagram);
    HeldViews.Datagram.reset();
    Context->Io.restart();

    const auto Result = Finalize(Context->Io, Active);

    ASSERT_TRUE(Result);
    EXPECT_TRUE(State->PhysicallyRetired.load(std::memory_order_acquire));
    EXPECT_EQ(State->CancelCalls.load(std::memory_order_relaxed), 1U);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_relaxed), 1U);
    EXPECT_EQ(State->DrainCalls.load(std::memory_order_relaxed), 1U);
    EXPECT_EQ(Storage->Pending(), 0U);
    EXPECT_TRUE(Activity->IsRetired());
    EXPECT_TRUE(WeakDatagram.expired());
}
