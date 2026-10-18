/**
 * @file NativeDatagramInboxTest.cpp
 * @brief 原生 QUIC 数据报队列的容量合同测试
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <span>
#include <vector>

#include <Prism/Protocols/Quic/Detail/DatagramInbox.hpp>
#include <Prism/Protocols/Quic/Native.hpp>

namespace
{

    using Prism::Quic::Detail::DatagramInbox;
    using Prism::Quic::NativeConnectionHealth;

    TEST(NativeDatagramInbox, DequeuePreservesFifoAndReturnsByteBudget)
    {
        DatagramInbox Inbox(DatagramInbox::Limits{.MaxDatagrams = 3, .MaxBytes = 6});
        const std::array<std::byte, 3> First{std::byte{0x11}, std::byte{0x12}, std::byte{0x13}};
        const std::array<std::byte, 3> Second{std::byte{0x21}, std::byte{0x22}, std::byte{0x23}};
        const std::array<std::byte, 3> Third{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}};

        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(First)));
        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(Second)));
        EXPECT_EQ(Inbox.PendingCount(), 2U);
        EXPECT_EQ(Inbox.PendingBytes(), 6U);

        const auto DequeuedFirst = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedFirst.has_value());
        EXPECT_EQ(*DequeuedFirst,
                  (std::vector<std::byte>{std::byte{0x11}, std::byte{0x12}, std::byte{0x13}}));
        EXPECT_EQ(Inbox.PendingCount(), 1U);
        EXPECT_EQ(Inbox.PendingBytes(), 3U);

        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(Third)));
        const auto DequeuedSecond = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedSecond.has_value());
        EXPECT_EQ(*DequeuedSecond,
                  (std::vector<std::byte>{std::byte{0x21}, std::byte{0x22}, std::byte{0x23}}));
        const auto DequeuedThird = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedThird.has_value());
        EXPECT_EQ(*DequeuedThird,
                  (std::vector<std::byte>{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}}));
        EXPECT_EQ(Inbox.PendingCount(), 0U);
        EXPECT_EQ(Inbox.PendingBytes(), 0U);
        EXPECT_EQ(Inbox.DroppedCount(), 0U);
    }

    TEST(NativeDatagramInbox, DatagramLimitDropsNewestAndRecovers)
    {
        DatagramInbox Inbox(DatagramInbox::Limits{.MaxDatagrams = 2, .MaxBytes = 16});
        const std::array<std::byte, 1> First{std::byte{0x41}};
        const std::array<std::byte, 1> Second{std::byte{0x42}};
        const std::array<std::byte, 1> Newest{std::byte{0x43}};

        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(First)));
        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(Second)));
        EXPECT_FALSE(Inbox.Enqueue(std::span<const std::byte>(Newest)));
        EXPECT_EQ(Inbox.PendingCount(), 2U);
        EXPECT_EQ(Inbox.PendingBytes(), 2U);
        EXPECT_EQ(Inbox.DroppedCount(), 1U);

        const auto DequeuedFirst = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedFirst.has_value());
        EXPECT_EQ(*DequeuedFirst, (std::vector<std::byte>{std::byte{0x41}}));
        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(Newest)));

        const auto DequeuedSecond = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedSecond.has_value());
        EXPECT_EQ(*DequeuedSecond, (std::vector<std::byte>{std::byte{0x42}}));
        const auto DequeuedNewest = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedNewest.has_value());
        EXPECT_EQ(*DequeuedNewest, (std::vector<std::byte>{std::byte{0x43}}));
        EXPECT_EQ(Inbox.PendingCount(), 0U);
        EXPECT_EQ(Inbox.PendingBytes(), 0U);
        EXPECT_EQ(Inbox.DroppedCount(), 1U);
    }

    TEST(NativeDatagramInbox, ByteLimitAllowsExactBoundAndReturnsBudget)
    {
        DatagramInbox Inbox(DatagramInbox::Limits{.MaxDatagrams = 4, .MaxBytes = 5});
        const std::array<std::byte, 2> First{std::byte{0x51}, std::byte{0x52}};
        const std::array<std::byte, 3> Second{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
        const std::array<std::byte, 2> Newest{std::byte{0x71}, std::byte{0x72}};

        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(First)));
        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(Second)));
        EXPECT_EQ(Inbox.PendingCount(), 2U);
        EXPECT_EQ(Inbox.PendingBytes(), 5U);
        EXPECT_FALSE(Inbox.Enqueue(std::span<const std::byte>(Newest)));
        EXPECT_EQ(Inbox.PendingCount(), 2U);
        EXPECT_EQ(Inbox.PendingBytes(), 5U);
        EXPECT_EQ(Inbox.DroppedCount(), 1U);

        const auto DequeuedFirst = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedFirst.has_value());
        EXPECT_EQ(*DequeuedFirst, (std::vector<std::byte>{std::byte{0x51}, std::byte{0x52}}));
        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(Newest)));

        const auto DequeuedSecond = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedSecond.has_value());
        EXPECT_EQ(*DequeuedSecond,
                  (std::vector<std::byte>{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}}));
        const auto DequeuedNewest = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedNewest.has_value());
        EXPECT_EQ(*DequeuedNewest, (std::vector<std::byte>{std::byte{0x71}, std::byte{0x72}}));
        EXPECT_EQ(Inbox.PendingCount(), 0U);
        EXPECT_EQ(Inbox.PendingBytes(), 0U);
        EXPECT_EQ(Inbox.DroppedCount(), 1U);
    }

    TEST(NativeDatagramInbox, EmptyDatagramConsumesCountButNoBytes)
    {
        DatagramInbox Inbox(DatagramInbox::Limits{.MaxDatagrams = 1, .MaxBytes = 2});
        const std::array<std::byte, 2> Payload{std::byte{0x81}, std::byte{0x82}};
        const std::span<const std::byte> Empty;

        ASSERT_TRUE(Inbox.Enqueue(Empty));
        EXPECT_EQ(Inbox.PendingCount(), 1U);
        EXPECT_EQ(Inbox.PendingBytes(), 0U);
        EXPECT_FALSE(Inbox.Enqueue(Empty));
        EXPECT_EQ(Inbox.DroppedCount(), 1U);

        const auto DequeuedEmpty = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedEmpty.has_value());
        EXPECT_TRUE(DequeuedEmpty->empty());
        EXPECT_EQ(Inbox.PendingCount(), 0U);
        EXPECT_EQ(Inbox.PendingBytes(), 0U);
        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(Payload)));
        EXPECT_EQ(Inbox.PendingCount(), 1U);
        EXPECT_EQ(Inbox.PendingBytes(), 2U);
    }

    TEST(NativeDatagramInbox, OversizedDatagramIsDroppedWithoutChangingQueue)
    {
        DatagramInbox Inbox(DatagramInbox::Limits{.MaxDatagrams = 2, .MaxBytes = 3});
        const std::array<std::byte, 1> First{std::byte{0x81}};
        const std::array<std::byte, 4> Oversized{
            std::byte{0x91}, std::byte{0x92}, std::byte{0x93}, std::byte{0x94}};
        const std::array<std::byte, 3> ExactBound{std::byte{0xA1}, std::byte{0xA2}, std::byte{0xA3}};

        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(First)));
        EXPECT_FALSE(Inbox.Enqueue(std::span<const std::byte>(Oversized)));
        EXPECT_EQ(Inbox.PendingCount(), 1U);
        EXPECT_EQ(Inbox.PendingBytes(), 1U);
        EXPECT_EQ(Inbox.DroppedCount(), 1U);

        const auto DequeuedFirst = Inbox.Dequeue();
        ASSERT_TRUE(DequeuedFirst.has_value());
        EXPECT_EQ(*DequeuedFirst, (std::vector<std::byte>{std::byte{0x81}}));
        ASSERT_TRUE(Inbox.Enqueue(std::span<const std::byte>(ExactBound)));
        EXPECT_EQ(Inbox.PendingCount(), 1U);
        EXPECT_EQ(Inbox.PendingBytes(), 3U);
        EXPECT_EQ(Inbox.DroppedCount(), 1U);
    }

    TEST(NativeDatagramInbox, DroppedDatagramsDoNotChangeHealthStatus)
    {
        NativeConnectionHealth Health{
            .SocketReady = true,
            .ReceiveLoopReady = true,
            .HandshakeReady = true,
            .ProtocolReady = true,
            .Closed = false,
            .BoundedFailure = false,
            .DroppedDatagrams = 1};

        EXPECT_TRUE(Health.Healthy());
        Health.ProtocolReady = false;
        EXPECT_FALSE(Health.Healthy());
    }

} // namespace
