/**
 * @file NativeDatagramInboxTest.cpp
 * @brief 原生 QUIC 数据报队列的容量合同测试
 */

#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>
#include <Prism/Protocols/Quic/Detail/NativeConnectionProviders.hpp>
#include <Prism/Protocols/Quic/Detail/NativeConnectionState.hpp>
#include <Prism/Protocols/Quic/Detail/DatagramInbox.hpp>
#include <Prism/Protocols/Quic/Native.hpp>

namespace Prism::Quic::Detail
{
    struct NativeConnectionDatagramTestAccess final
    {
        [[nodiscard]] static auto EnqueueWithoutNotification(
            NativeConnection &Connection,
            const std::span<const std::byte> Data) -> bool
        {
            return Connection.Datagram_ && Connection.Datagram_->Inbox.Enqueue(Data);
        }
    };
}

namespace
{

    namespace Net = boost::asio;
    using DatagramSignal = Net::experimental::channel<void(boost::system::error_code)>;
    using Prism::Quic::Detail::DatagramInbox;
    using Prism::Quic::Detail::NativeConnection;
    using Prism::Quic::Detail::NativeConnectionDatagramTestAccess;
    using Prism::Quic::NativeConnectionHealth;

    struct ClosedProviderObservation final
    {
        bool Enqueued{false};
        bool ClosedAfterCommand{false};
        std::array<std::size_t, 4> ReceiveCounts{};
        std::array<std::error_code, 2> TerminalErrors{};
        std::vector<std::byte> Received;
        std::size_t PendingDatagrams{0U};
        std::size_t PendingBytes{0U};
    };

    struct DatagramReceiveObservation final
    {
        std::size_t Bytes{0U};
        std::error_code Error;
        std::array<std::byte, 8> Buffer{};
    };

    struct PendingDatagramReader final
    {
        explicit PendingDatagramReader(Net::any_io_executor Executor)
            : Started(Executor, 1), Completed(Executor, 1)
        {
        }

        DatagramSignal Started;
        DatagramSignal Completed;
        std::optional<DatagramReceiveObservation> Result;
        std::exception_ptr Exception;
    };

    struct ConnectionCloseObservation final
    {
        bool Queued{false};
        bool ProviderClosed{false};
        bool OwnerDrained{false};
        bool OwnerRetired{false};
        DatagramReceiveObservation First;
        std::array<std::error_code, 2> TerminalErrors{};
    };

    auto ReceiveDatagramOnce(Prism::Quic::SharedDatagramProvider Provider)
        -> Net::awaitable<DatagramReceiveObservation>
    {
        DatagramReceiveObservation Result;
        Result.Bytes = co_await Provider->Receive(Result.Buffer, Result.Error);
        co_return Result;
    }

    auto StartPendingDatagramRead(
        Prism::Quic::SharedDatagramProvider Provider,
        std::shared_ptr<PendingDatagramReader> Reader)
        -> Net::awaitable<DatagramReceiveObservation>
    {
        (void)Reader->Started.try_send(boost::system::error_code{});
        co_return co_await ReceiveDatagramOnce(std::move(Provider));
    }

    auto RunConnectionCloseWithPendingReceive(Net::any_io_executor Executor)
        -> Net::awaitable<ConnectionCloseObservation>
    {
        Prism::Quic::ClientOptions Options{};
        Options.Executor = Executor;
        auto Connection = std::make_shared<NativeConnection>(Options);
        const auto Provider = Connection->DatagramProvider();
        auto Reader = std::make_shared<PendingDatagramReader>(Executor);
        Net::co_spawn(Executor, StartPendingDatagramRead(Provider, Reader),
            [Reader](std::exception_ptr Exception, DatagramReceiveObservation Result)
            {
                Reader->Exception = std::move(Exception);
                Reader->Result.emplace(std::move(Result));
                (void)Reader->Completed.try_send(boost::system::error_code{});
            });
        co_await Reader->Started.async_receive(Net::use_awaitable);
        co_await Net::post(Executor, Net::use_awaitable);

        const std::array Packet{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}};
        ConnectionCloseObservation Observation;
        Observation.Queued = NativeConnectionDatagramTestAccess::EnqueueWithoutNotification(
            *Connection, Packet);
        Connection->Close();
        co_await Reader->Completed.async_receive(Net::use_awaitable);
        if (!Reader->Exception && Reader->Result)
        {
            Observation.First = std::move(*Reader->Result);
        }
        Observation.ProviderClosed = Provider->IsClosed();
        for (auto &Error : Observation.TerminalErrors)
        {
            const auto Terminal = co_await ReceiveDatagramOnce(Provider);
            Error = Terminal.Error;
        }
        const auto Drain = co_await Connection->Drain();
        Observation.OwnerDrained = Drain.has_value();
        Observation.OwnerRetired = Connection->IsRetired();
        co_return Observation;
    }

    auto RunClosedProviderQueue(
        Net::any_io_executor Executor) -> Net::awaitable<ClosedProviderObservation>
    {
        Prism::Quic::ClientOptions Options{};
        Options.Executor = Executor;
        auto Connection = std::make_shared<Prism::Quic::Detail::NativeConnection>(Options);
        auto State = std::make_shared<Prism::Quic::Detail::DatagramState>(
            Executor, DatagramInbox::Limits{.MaxDatagrams = 2U, .MaxBytes = 8U});
        auto Provider = std::make_shared<Prism::Quic::Detail::NativeDatagram>(Connection, State);
        const std::array First{std::byte{0x11}, std::byte{0x12}};
        const std::array Second{std::byte{0x21}, std::byte{0x22}, std::byte{0x23}};
        ClosedProviderObservation Observation;
        Observation.Enqueued = State->Inbox.Enqueue(std::span<const std::byte>(First)) &&
            State->Inbox.Enqueue(std::span<const std::byte>(Second));

        Provider->Close();
        Observation.ClosedAfterCommand = Provider->IsClosed();
        std::array<std::byte, 8> Buffer{};
        for (std::size_t Index = 0; Index < Observation.ReceiveCounts.size(); ++Index)
        {
            std::error_code ErrorCode;
            Observation.ReceiveCounts[Index] = co_await Provider->Receive(
                std::span<std::byte>(Buffer), ErrorCode);
            if (Index < 2U)
            {
                Observation.Received.insert(
                    Observation.Received.end(), Buffer.begin(),
                    Buffer.begin() + static_cast<std::ptrdiff_t>(Observation.ReceiveCounts[Index]));
            }
            else
            {
                Observation.TerminalErrors[Index - 2U] = ErrorCode;
            }
        }
        Observation.PendingDatagrams = State->Inbox.PendingCount();
        Observation.PendingBytes = State->Inbox.PendingBytes();
        co_return Observation;
    }

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

    TEST(NativeDatagramInbox, ProviderCloseDrainsQueuedPacketsBeforeStickyBrokenPipe)
    {
        Net::io_context Io;
        std::exception_ptr Exception;
        std::optional<ClosedProviderObservation> Observation;
        Net::co_spawn(Io, RunClosedProviderQueue(Io.get_executor()),
            [&Exception, &Observation](
                std::exception_ptr Error, ClosedProviderObservation Value)
            {
                Exception = std::move(Error);
                Observation = std::move(Value);
            });
        Io.run();

        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Observation.has_value());
        EXPECT_TRUE(Observation->Enqueued);
        EXPECT_TRUE(Observation->ClosedAfterCommand);
        EXPECT_EQ(Observation->ReceiveCounts[0], 2U);
        EXPECT_EQ(Observation->ReceiveCounts[1], 3U);
        EXPECT_EQ(Observation->ReceiveCounts[2], 0U);
        EXPECT_EQ(Observation->ReceiveCounts[3], 0U);
        EXPECT_EQ(Observation->Received,
            (std::vector<std::byte>{std::byte{0x11}, std::byte{0x12}, std::byte{0x21},
                std::byte{0x22}, std::byte{0x23}}));
        EXPECT_EQ(Observation->TerminalErrors[0],
            Prism::make_error_code(Prism::Error::BrokenPipe));
        EXPECT_EQ(Observation->TerminalErrors[1],
            Prism::make_error_code(Prism::Error::BrokenPipe));
        EXPECT_EQ(Observation->PendingDatagrams, 0U);
        EXPECT_EQ(Observation->PendingBytes, 0U);
    }

    TEST(NativeDatagramInbox, ConnectionCloseDrainsQueuedPacketBeforeStickyBrokenPipe)
    {
        Net::io_context Io;
        std::exception_ptr Exception;
        std::optional<ConnectionCloseObservation> Observation;
        Net::co_spawn(Io, RunConnectionCloseWithPendingReceive(Io.get_executor()),
            [&Exception, &Observation](std::exception_ptr Error, ConnectionCloseObservation Value)
            {
                Exception = std::move(Error);
                Observation = std::move(Value);
            });
        Io.run();

        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Observation.has_value());
        EXPECT_TRUE(Observation->Queued);
        EXPECT_TRUE(Observation->ProviderClosed);
        EXPECT_EQ(Observation->First.Bytes, 3U);
        EXPECT_FALSE(Observation->First.Error);
        EXPECT_EQ(Observation->First.Buffer[0], std::byte{0x31});
        EXPECT_EQ(Observation->First.Buffer[1], std::byte{0x32});
        EXPECT_EQ(Observation->First.Buffer[2], std::byte{0x33});
        EXPECT_EQ(Observation->TerminalErrors[0],
            Prism::make_error_code(Prism::Error::BrokenPipe));
        EXPECT_EQ(Observation->TerminalErrors[1],
            Prism::make_error_code(Prism::Error::BrokenPipe));
        EXPECT_TRUE(Observation->OwnerDrained);
        EXPECT_TRUE(Observation->OwnerRetired);
    }

} // namespace
