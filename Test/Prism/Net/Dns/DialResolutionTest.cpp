/**
 * @file DialResolutionTest.cpp
 * @brief DNS 解析器的正向与负向缓存行为。
 */

#include <gtest/gtest.h>
#include "ResolverTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
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
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/Dns/Detail/ResolverFailure.hpp>
#include <Prism/Net/Datagram/Egress.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Network = Prism::Network;

    auto RunResolveLocalhost(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        Network::Dns::Resolver Resolver(IoContext.get_executor());
        auto Addresses = co_await Resolver.AsyncResolve("localhost");
        if (!Addresses)
        {
            ADD_FAILURE() << "localhost resolution failed";
            co_return;
        }
        EXPECT_FALSE(Addresses->Empty());
        auto CachedAddresses = co_await Resolver.AsyncResolve("localhost");
        if (!CachedAddresses)
        {
            ADD_FAILURE() << "cached localhost resolution failed";
            co_return;
        }
        EXPECT_GT(Resolver.HitCount(), 0u);
        EXPECT_TRUE(!Addresses->Empty() && !CachedAddresses->Empty());
    }

    auto RunNegativeCache(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Server = std::make_shared<MiniDnsServer>(
            IoContext, MiniDnsServer::Behavior::NxDomain);
        Server->Start();
        Network::Dns::Config Configuration;
        Configuration.Servers = {Server->MakeConfig()};
        Configuration.DisableIpv6 = true;
        Network::Dns::Resolver Resolver(IoContext.get_executor(), Configuration);

        auto Addresses = co_await Resolver.AsyncResolve("nx.local");
        auto CachedAddresses = co_await Resolver.AsyncResolve("nx.local");
        EXPECT_FALSE(Addresses);
        EXPECT_FALSE(CachedAddresses);
        if (!Addresses)
        {
            EXPECT_EQ(Addresses.error().Code, Prism::Fault::Code::DnsFailed);
        }
        if (!CachedAddresses)
        {
            EXPECT_EQ(CachedAddresses.error().Code, Prism::Fault::Code::DnsFailed);
        }
        EXPECT_GT(Resolver.HitCount(), 0u);
        EXPECT_EQ(Resolver.Size(), 1U);
        EXPECT_EQ(Server->QueryCount(), 1U);
        const auto Shutdown = co_await Resolver.Shutdown();
        EXPECT_TRUE(Shutdown.has_value());
        Server->Close();
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
        Prism::Contract::DatagramExchangeRequest Request;
        Request.Target = {*Network::ParseHost("127.0.0.1"),
                          Receiver.local_endpoint().port()};
        Request.Payload = std::move(Payload);
        Request.Timeout = std::chrono::milliseconds(50);

        const auto Result = co_await Egress.Exchange(std::move(Request));
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Timeout);
        EXPECT_EQ(Result.Uploaded, PayloadSize);

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
            ADD_FAILURE() << "egress packet was not received before the deadline";
            co_return;
        }
        const auto ReceivedBytes = std::get<0>(ReceivedOutcome);
        EXPECT_EQ(ReceivedBytes, PayloadSize);
    }

    struct EgressCompletion final
    {
        std::exception_ptr Error;
        std::optional<Prism::Contract::DatagramExchangeResult> Result;
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

        Prism::Contract::DatagramExchangeRequest Request;
        Request.Target = {*Network::ParseHost("127.0.0.1"),
                          Receiver.local_endpoint().port()};
        Request.Payload = {std::byte{0x41}, std::byte{0x42}, std::byte{0x43}};
        Request.Timeout = std::chrono::seconds(2);
        Net::co_spawn(
            IoContext, Egress.Exchange(std::move(Request)),
            Net::bind_cancellation_slot(Cancellation->slot(),
                [Completion, Done](std::exception_ptr Error,
                                   Prism::Contract::DatagramExchangeResult Result)
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
        EXPECT_EQ(Completion->Result->Failure.Code, Prism::Fault::Code::Canceled);
        EXPECT_EQ(Completion->Result->Uploaded, 3U);
    }

    auto RunEgressResolverFailure(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Server = std::make_shared<MiniDnsServer>(
            IoContext, MiniDnsServer::Behavior::NxDomain);
        Server->Start();
        Network::Dns::Config Configuration;
        Configuration.Servers = {Server->MakeConfig()};
        Configuration.DisableIpv6 = true;
        auto Resolver = std::make_shared<Network::Dns::Resolver>(
            IoContext.get_executor(), Configuration);
        Network::DatagramEgress Egress(Resolver);
        Prism::Contract::DatagramExchangeRequest Request;
        Request.Target = {*Network::ParseHost("nx.local"), 53U};
        Request.Payload = {std::byte{0x41}};
        Request.Timeout = std::chrono::seconds(4);
        const auto Result = co_await Egress.Exchange(std::move(Request));
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::DnsFailed);
        EXPECT_FALSE(static_cast<bool>(Result.Failure.Native));
        EXPECT_EQ(Result.Uploaded, 0U);
        const auto Shutdown = co_await Resolver->Shutdown();
        EXPECT_TRUE(Shutdown.has_value());
        Server->Close();
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

        Prism::Contract::DatagramExchangeRequest Request;
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
        Prism::Testing::RunCoro(IoContext, RunResolveLocalhost(IoContext));
    }

    TEST(DnsDialSuite, NegativeCache)
    {
        Net::io_context IoContext;
        Prism::Testing::RunCoro(IoContext, RunNegativeCache(IoContext));
    }

    TEST(DnsDialSuite, EgressTimeoutRetainsUploadedBytes)
    {
        Net::io_context IoContext;
        Prism::Testing::RunCoro(IoContext, RunEgressTimeoutProgress(IoContext, 3));
    }

    TEST(DnsDialSuite, EgressTimeoutRetainsZeroLengthDatagram)
    {
        Net::io_context IoContext;
        Prism::Testing::RunCoro(IoContext, RunEgressTimeoutProgress(IoContext, 0));
    }

    TEST(DnsDialSuite, EgressCancellationRetainsUploadedBytes)
    {
        Net::io_context IoContext;
        Prism::Testing::RunCoro(IoContext, RunEgressCancellationProgress(IoContext));
    }

    TEST(DnsDialSuite, EgressResolverReturnsNxDomainFailure)
    {
        Net::io_context IoContext;
        Prism::Testing::RunCoro(IoContext, RunEgressResolverFailure(IoContext));
    }

    TEST(DnsDialSuite, ResolverFailurePreservesHostNotFoundNativeCause)
    {
        const auto NativeCause = Net::error::make_error_code(Net::error::host_not_found);
        const auto Failure = Network::Dns::Detail::ResolverFailureFromBoost(NativeCause);

        EXPECT_EQ(Failure.Code, Prism::Fault::Code::DnsFailed);
        EXPECT_TRUE(Failure.Native);
        EXPECT_EQ(Failure.Native, static_cast<std::error_code>(NativeCause));
    }

    TEST(DnsDialSuite, EgressAcceptsAnEmptyReplyDatagram)
    {
        Net::io_context IoContext;
        Prism::Testing::RunCoro(IoContext, RunEgressEmptyReply(IoContext));
    }

} // namespace
