/**
 * @file UdpExceptionTest.cpp
 * @brief SOCKS5 UDP_ASSOCIATE resolver 异常映射与真实退役测试。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Protocols/Socks5/UdpAssoc.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <gtest/gtest.h>

#include "TcpPair.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    namespace TestSupport = Prism::Socks5UdpTestSupport;
    using Udp = Net::ip::udp;
    using Failure = Prism::Fault::Failure;

    constexpr auto ReplySize = std::size_t{10};
    using AssociationRunResult = std::expected<void, Failure>;

    struct AssociationRunCompletion final
    {
        explicit AssociationRunCompletion(Net::any_io_executor Executor)
            : Finished(std::move(Executor), 1)
        {
        }

        Net::experimental::channel<void(boost::system::error_code)> Finished;
        AssociationRunResult Result{
            std::unexpected(Failure{Prism::Fault::Code::Blocked})};
        std::exception_ptr Exception;
    };

    enum class ExceptionKind
    {
        Standard,
        Boost,
        Unknown,
    };

    struct ExceptionOutcome final
    {
        bool BindReplyReceived{false};
        bool RunCompleted{false};
        bool RunFailed{false};
        Failure RunFailure{Prism::Fault::Code::Blocked};
        bool ClientEndpointMatches{false};
        std::size_t DatagramCount{0U};
        bool DrainSucceeded{false};
        Failure DrainFailure{Prism::Fault::Code::Blocked};
        bool ActivityRetired{false};
        bool ClientDatagramsClosed{false};
        bool ClientControlClosed{false};
    };

    /** @brief 计算异常类型应有的稳定 typed/native 投影。 */
    [[nodiscard]] auto ExpectedFailure(ExceptionKind Exception) -> Failure
    {
        switch (Exception)
        {
            case ExceptionKind::Standard:
            {
                const auto Native = std::make_error_code(std::errc::permission_denied);
                return {Prism::Fault::ToCode(Native), Native};
            }
            case ExceptionKind::Boost:
            {
                const auto Native = static_cast<std::error_code>(
                    boost::system::errc::make_error_code(
                        boost::system::errc::permission_denied));
                return {Prism::Fault::ToCode(Native), Native};
            }
            case ExceptionKind::Unknown:
                return {Prism::Fault::Code::IoError};
        }
        return {Prism::Fault::Code::Blocked};
    }

    /** @brief 在具名协程帧内投递异常，避免 coroutine lambda 借用闭包状态。 */
    auto RaiseResolveException(ExceptionKind Exception)
        -> Net::awaitable<std::expected<Udp::endpoint, Failure>>
    {
        switch (Exception)
        {
            case ExceptionKind::Standard:
                throw std::system_error(std::make_error_code(std::errc::permission_denied));
            case ExceptionKind::Boost:
                throw boost::system::system_error(
                    boost::system::errc::make_error_code(
                        boost::system::errc::permission_denied));
            case ExceptionKind::Unknown:
                throw std::runtime_error("unexpected association failure");
        }
        co_return std::unexpected(Failure{Prism::Fault::Code::IoError});
    }

    /** @brief 经 UDP_ASSOCIATE 公共 Run/Drain 路径投递一次 resolver 异常。 */
    auto RunExceptionScenario(
        Net::io_context& IoContext,
        ExceptionKind Exception,
        ExceptionOutcome& Outcome)
        -> Net::awaitable<void>
    {
        TestSupport::TcpPair Pair(IoContext.get_executor());
        co_await TestSupport::MakeTcpPair(IoContext, Pair);
        auto Connection = std::make_shared<Socks5::Conn<>>(
            std::make_shared<Prism::Transport::Reliable>(std::move(Pair.Server)));
        Socks5::UdpAssocOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds::zero();
        Options.Resolve = [Exception](const Socks5::Address&)
        {
            return RaiseResolveException(Exception);
        };
        auto Association = std::make_shared<Socks5::UdpAssoc>(
            IoContext.get_executor(), std::move(Connection), std::move(Options));
        const auto Activity = Association->Activity();
        auto Completion = std::make_shared<AssociationRunCompletion>(IoContext.get_executor());
        Net::co_spawn(IoContext, Association->Run(),
            [Completion](std::exception_ptr RunException,
                         AssociationRunResult Result)
            {
                Completion->Exception = std::move(RunException);
                Completion->Result = std::move(Result);
                (void)Completion->Finished.try_send(boost::system::error_code{});
            });

        std::array<std::byte, ReplySize> Reply{};
        const auto ReplyBytes = co_await Net::async_read(
            Pair.Client, Net::buffer(Reply), Net::use_awaitable);
        Outcome.BindReplyReceived = ReplyBytes == Reply.size();

        Udp::socket ClientDatagrams(IoContext.get_executor());
        ClientDatagrams.open(Udp::v4());
        ClientDatagrams.bind(Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        if (Outcome.BindReplyReceived)
        {
            const std::array<std::uint8_t, 19> Frame{
                0x00, 0x00, 0x00, 0x03, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.',
                'c', 'o', 'm', 0, 53, 0x5A};
            const auto Sent = co_await ClientDatagrams.async_send_to(
                Net::buffer(Frame), Association->BindEndpoint(), Net::use_awaitable);
            EXPECT_EQ(Sent, Frame.size());
        }
        else
        {
            Association->Close();
        }

        co_await Completion->Finished.async_receive(Net::use_awaitable);
        Outcome.RunCompleted = true;
        if (Completion->Exception) std::rethrow_exception(Completion->Exception);
        Outcome.RunFailed = !Completion->Result;
        if (!Completion->Result) Outcome.RunFailure = Completion->Result.error();
        const auto ClientUdpEndpoint = ClientDatagrams.local_endpoint();
        Outcome.ClientEndpointMatches =
            ClientUdpEndpoint.address() == Pair.Client.local_endpoint().address();
        Outcome.DatagramCount = Association->DatagramCount();

        const auto Drain = co_await Activity->Drain();
        Outcome.DrainSucceeded = Drain.has_value();
        if (!Drain) Outcome.DrainFailure = Drain.error();
        Outcome.ActivityRetired = Activity->IsRetired();
        if (ClientDatagrams.is_open()) ClientDatagrams.close();
        Outcome.ClientDatagramsClosed = !ClientDatagrams.is_open();
        Pair.Client.close();
        Outcome.ClientControlClosed = !Pair.Client.is_open();
    }

    /** @brief 在同一 executor 上顺序退休多条关联，覆盖 worker 复用路径。 */
    auto RunExceptionScenarios(
        Net::io_context& IoContext,
        std::array<ExceptionOutcome, 3>& Outcomes)
        -> Net::awaitable<void>
    {
        co_await RunExceptionScenario(IoContext, ExceptionKind::Standard, Outcomes[0]);
        co_await RunExceptionScenario(IoContext, ExceptionKind::Boost, Outcomes[1]);
        co_await RunExceptionScenario(IoContext, ExceptionKind::Unknown, Outcomes[2]);
    }

    TEST(Socks5DeferredReply, AssociationExceptionReturnsMappedNativeFailure)
    {
        Net::io_context IoContext;
        std::array<ExceptionOutcome, 3> Outcomes{};
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, RunExceptionScenarios(IoContext, Outcomes),
            [&Exception](std::exception_ptr Value) { Exception = std::move(Value); });
        IoContext.run();
        if (Exception) std::rethrow_exception(Exception);

        constexpr std::array ExceptionKinds{
            ExceptionKind::Standard,
            ExceptionKind::Boost,
            ExceptionKind::Unknown};
        for (std::size_t Index = 0; Index < Outcomes.size(); ++Index)
        {
            const auto& Outcome = Outcomes[Index];
            const auto Expected = ExpectedFailure(ExceptionKinds[Index]);
            EXPECT_TRUE(Outcome.BindReplyReceived);
            EXPECT_TRUE(Outcome.RunCompleted);
            EXPECT_TRUE(Outcome.RunFailed);
            EXPECT_EQ(Outcome.RunFailure.Code, Expected.Code);
            EXPECT_EQ(Outcome.RunFailure.Native, Expected.Native);
            EXPECT_TRUE(Outcome.ClientEndpointMatches);
            EXPECT_EQ(Outcome.DatagramCount, 1U);
            EXPECT_FALSE(Outcome.DrainSucceeded);
            EXPECT_EQ(Outcome.DrainFailure.Code, Expected.Code);
            EXPECT_EQ(Outcome.DrainFailure.Native, Expected.Native);
            EXPECT_TRUE(Outcome.ActivityRetired);
            EXPECT_TRUE(Outcome.ClientDatagramsClosed);
            EXPECT_TRUE(Outcome.ClientControlClosed);
        }
    }
}
