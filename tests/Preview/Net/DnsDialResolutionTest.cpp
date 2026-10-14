/**
 * @file DnsDialResolutionTest.cpp
 * @brief DNS 解析器的正向与负向缓存行为。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/steady_timer.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Net/Datagram/Egress.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Network = Preview::Network;

    auto RunResolveLocalhost(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        Network::Dns::Resolver Resolver(IoContext.get_executor());
        auto Addresses = co_await Resolver.AsyncResolve("localhost");
        ASSERT_TRUE(Addresses);
        EXPECT_FALSE(Addresses->Empty());
        auto CachedAddresses = co_await Resolver.AsyncResolve("localhost");
        ASSERT_TRUE(CachedAddresses);
        EXPECT_GT(Resolver.HitCount(), 0u);
        EXPECT_TRUE(!Addresses->Empty() && !CachedAddresses->Empty());
    }

    auto RunNegativeCache(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        Network::Dns::Resolver Resolver(IoContext.get_executor());
        auto Addresses = co_await Resolver.AsyncResolve("nonexistent12345.test.invalid");
        auto CachedAddresses = co_await Resolver.AsyncResolve("nonexistent12345.test.invalid");
        ASSERT_FALSE(Addresses);
        ASSERT_FALSE(CachedAddresses);
        EXPECT_GT(Resolver.HitCount(), 0u);
        EXPECT_EQ(Addresses.error().Code, Preview::Fault::Code::DnsFailed);
        EXPECT_EQ(CachedAddresses.error().Code, Addresses.error().Code);
    }

    auto RunEgressTimeoutProgress(Net::io_context &IoContext,
                                  const std::size_t PayloadSize) -> Net::awaitable<void>
    {
        using Udp = Net::ip::udp;
        Udp::socket Receiver(IoContext.get_executor(),
            Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto Resolver = std::make_shared<Network::Dns::Resolver>(IoContext.get_executor());
        Network::DatagramEgress Egress(Resolver);
        std::vector<std::byte> Payload(PayloadSize, std::byte{0x41});
        Preview::Contract::DatagramExchangeRequest Request;
        Request.Target = {*Network::ParseHost("127.0.0.1"),
                          Receiver.local_endpoint().port()};
        Request.Payload = std::move(Payload);
        Request.Timeout = std::chrono::milliseconds(50);

        const auto Result = co_await Egress.Exchange(std::move(Request));
        EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Timeout);
        EXPECT_EQ(Result.Uploaded, PayloadSize);

        std::array<std::byte, 1> Received{};
        Udp::endpoint Source;
        boost::system::error_code Error;
        Receiver.non_blocking(true, Error);
        if (Error)
        {
            ADD_FAILURE() << "could not make receiver non-blocking: " << Error.message();
            co_return;
        }
        const auto ReceivedBytes = Receiver.receive_from(Net::buffer(Received), Source, Error);
        EXPECT_FALSE(Error);
        EXPECT_EQ(ReceivedBytes, PayloadSize);
    }

    struct EgressCompletion final
    {
        std::exception_ptr Error;
        std::optional<Preview::Contract::DatagramExchangeResult> Result;
    };

    auto RunEgressCancellationProgress(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        using Udp = Net::ip::udp;
        Udp::socket Receiver(IoContext.get_executor(),
            Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto Resolver = std::make_shared<Network::Dns::Resolver>(IoContext.get_executor());
        Network::DatagramEgress Egress(Resolver);
        auto Cancellation = std::make_shared<Net::cancellation_signal>();
        auto Done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            IoContext.get_executor(), 1);
        auto Completion = std::make_shared<EgressCompletion>();

        Preview::Contract::DatagramExchangeRequest Request;
        Request.Target = {*Network::ParseHost("127.0.0.1"),
                          Receiver.local_endpoint().port()};
        Request.Payload = {std::byte{0x41}, std::byte{0x42}, std::byte{0x43}};
        Request.Timeout = std::chrono::seconds(2);
        Net::co_spawn(
            IoContext, Egress.Exchange(std::move(Request)),
            Net::bind_cancellation_slot(Cancellation->slot(),
                [Completion, Done](std::exception_ptr Error,
                                   Preview::Contract::DatagramExchangeResult Result)
                {
                    Completion->Error = std::move(Error);
                    if (!Completion->Error)
                    {
                        Completion->Result = std::move(Result);
                    }
                    (void)Done->try_send(boost::system::error_code{});
                }));

        std::array<std::byte, 8> Received{};
        Udp::endpoint Source;
        Net::steady_timer ReceiveDeadline(IoContext.get_executor());
        ReceiveDeadline.expires_after(std::chrono::milliseconds(500));
        using Net::experimental::awaitable_operators::operator||;
        const auto ReceivedOutcome = co_await (
            Receiver.async_receive_from(Net::buffer(Received), Source, Net::use_awaitable) ||
            ReceiveDeadline.async_wait(Net::use_awaitable));
        if (ReceivedOutcome.index() != 0U)
        {
            ADD_FAILURE() << "egress did not send before the receive deadline";
            co_return;
        }
        Cancellation->emit(Net::cancellation_type::all);
        co_await Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(Completion->Error);
        if (!Completion->Result)
        {
            ADD_FAILURE() << "datagram exchange completed without a typed result";
            co_return;
        }
        EXPECT_EQ(Completion->Result->Failure.Code, Preview::Fault::Code::Canceled);
        EXPECT_EQ(Completion->Result->Uploaded, 3U);
    }

    auto RunEgressResolverFailure(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Resolver = std::make_shared<Network::Dns::Resolver>(IoContext.get_executor());
        Network::DatagramEgress Egress(Resolver);
        Preview::Contract::DatagramExchangeRequest Request;
        Request.Target = {*Network::ParseHost("nonexistent12345.test.invalid"), 53U};
        Request.Timeout = std::chrono::seconds(4);
        const auto Result = co_await Egress.Exchange(std::move(Request));
        EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::DnsFailed);
        EXPECT_TRUE(static_cast<bool>(Result.Failure.Native));
        EXPECT_EQ(Result.Uploaded, 0U);
    }

    auto ReplyWithEmptyDatagram(boost::asio::ip::udp::socket &Receiver)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 8> Request{};
        boost::asio::ip::udp::endpoint Source;
        (void)co_await Receiver.async_receive_from(
            Net::buffer(Request), Source, Net::use_awaitable);
        const std::array<std::byte, 0> Empty{};
        (void)co_await Receiver.async_send_to(Net::buffer(Empty), Source, Net::use_awaitable);
    }

    auto RunEgressEmptyReply(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        using Udp = Net::ip::udp;
        Udp::socket Receiver(IoContext.get_executor(),
            Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto Resolver = std::make_shared<Network::Dns::Resolver>(IoContext.get_executor());
        Network::DatagramEgress Egress(Resolver);
        Net::co_spawn(IoContext, ReplyWithEmptyDatagram(Receiver), Net::detached);

        Preview::Contract::DatagramExchangeRequest Request;
        Request.Target = {*Network::ParseHost("127.0.0.1"),
                          Receiver.local_endpoint().port()};
        Request.Payload = {std::byte{0x41}};
        const auto Result = co_await Egress.Exchange(std::move(Request));
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_TRUE(Result.Payload.empty());
        EXPECT_EQ(Result.Uploaded, 1U);
    }

    TEST(DnsDialSuite, ResolveLocalhost)
    {
        Net::io_context IoContext;
        Preview::Testing::RunCoro(IoContext, RunResolveLocalhost(IoContext));
    }

    TEST(DnsDialSuite, NegativeCache)
    {
        Net::io_context IoContext;
        Preview::Testing::RunCoro(IoContext, RunNegativeCache(IoContext));
    }

    TEST(DnsDialSuite, EgressTimeoutRetainsUploadedBytes)
    {
        Net::io_context IoContext;
        Preview::Testing::RunCoro(IoContext, RunEgressTimeoutProgress(IoContext, 3));
    }

    TEST(DnsDialSuite, EgressTimeoutRetainsZeroLengthDatagram)
    {
        Net::io_context IoContext;
        Preview::Testing::RunCoro(IoContext, RunEgressTimeoutProgress(IoContext, 0));
    }

    TEST(DnsDialSuite, EgressCancellationRetainsUploadedBytes)
    {
        Net::io_context IoContext;
        Preview::Testing::RunCoro(IoContext, RunEgressCancellationProgress(IoContext));
    }

    TEST(DnsDialSuite, EgressResolverPreservesNativeFailure)
    {
        Net::io_context IoContext;
        Preview::Testing::RunCoro(IoContext, RunEgressResolverFailure(IoContext));
    }

    TEST(DnsDialSuite, EgressAcceptsAnEmptyReplyDatagram)
    {
        Net::io_context IoContext;
        Preview::Testing::RunCoro(IoContext, RunEgressEmptyReply(IoContext));
    }

} // namespace
