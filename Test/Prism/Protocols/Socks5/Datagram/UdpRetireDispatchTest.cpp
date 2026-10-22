/**
 * @file UdpRetireDispatchTest.cpp
 * @brief SOCKS5 UDP_ASSOCIATE 回收投递拒绝后的重试测试。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Protocols/Socks5/UdpAssoc.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    using Tcp = Net::ip::tcp;
    using Failure = Prism::Fault::Failure;
    using RunResult = std::expected<void, Failure>;

    struct ReclaimerPostRetryScenario final
    {
        std::shared_ptr<Socks5::UdpAssoc> Association;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
        std::shared_ptr<Tcp::socket> ClientControl;
        std::optional<RunResult> FirstDrain;
        std::optional<RunResult> SecondDrain;
        bool RetiredAfterFirstDrain{false};
    };

    /** @brief 创建供 UdpAssoc 回收测试使用的本地 TCP 连接对。 */
    auto MakeTcpPair(Net::io_context &Io)
        -> Net::awaitable<std::pair<Tcp::socket, Tcp::socket>>
    {
        Tcp::acceptor Acceptor(Io, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Tcp::socket Client(Io.get_executor());
        co_await Client.async_connect(Acceptor.local_endpoint(), Net::use_awaitable);
        auto Server = co_await Acceptor.async_accept(Net::use_awaitable);
        co_return std::pair{std::move(Client), std::move(Server)};
    }

    /** @brief 驱动一次协程并向测试转交其异常。 */
    auto RunCoroutine(Net::io_context &Io, Net::awaitable<void> Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Io, std::move(Coroutine),
            [&Exception](std::exception_ptr Value) { Exception = std::move(Value); });
        Io.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /** @brief 在已停止的 executor 上创建尚未启动 Run 的关联。 */
    auto BuildReclaimerPostRetryScenario(
        Net::io_context &Io,
        ReclaimerPostRetryScenario &Scenario) -> Net::awaitable<void>
    {
        auto [Client, Server] = co_await MakeTcpPair(Io);
        Scenario.ClientControl = std::make_shared<Tcp::socket>(std::move(Client));
        auto Carrier = std::make_shared<Prism::Transport::Reliable>(std::move(Server));
        auto Connection = std::make_shared<Socks5::Conn<>>(std::move(Carrier));
        Socks5::UdpAssocOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds::zero();
        Scenario.Association = std::make_shared<Socks5::UdpAssoc>(
            Io.get_executor(), std::move(Connection), std::move(Options));
        Scenario.Activity = Scenario.Association->Activity();
        co_return;
    }

    /** @brief 重启 executor 后重试退役并记录两次 Drain 结果。 */
    auto RetryReclaimerPostScenario(
        ReclaimerPostRetryScenario &Scenario) -> Net::awaitable<void>
    {
        Scenario.FirstDrain = co_await Scenario.Activity->Drain();
        Scenario.RetiredAfterFirstDrain = Scenario.Activity->IsRetired();
        Scenario.SecondDrain = co_await Scenario.Activity->Drain();
        co_return;
    }

    TEST(Socks5UdpAssocRetirement, RetriesAfterStoppedExecutorRejectsReclaimerPost)
    {
        Net::io_context Io;
        ReclaimerPostRetryScenario Scenario;
        RunCoroutine(Io, BuildReclaimerPostRetryScenario(Io, Scenario));
        ASSERT_TRUE(Scenario.Association);
        ASSERT_TRUE(Scenario.Activity);
        ASSERT_TRUE(Io.stopped());

        Scenario.Association->Close();
        EXPECT_FALSE(Scenario.Activity->IsRetired());

        Io.restart();
        RunCoroutine(Io, RetryReclaimerPostScenario(Scenario));

        ASSERT_TRUE(Scenario.FirstDrain.has_value());
        ASSERT_FALSE(*Scenario.FirstDrain);
        EXPECT_EQ(Scenario.FirstDrain->error().Code, Prism::Fault::Code::Blocked);
        EXPECT_TRUE(Scenario.RetiredAfterFirstDrain);
        ASSERT_TRUE(Scenario.SecondDrain.has_value());
        EXPECT_TRUE(*Scenario.SecondDrain);
        EXPECT_TRUE(Scenario.Activity->IsRetired());

        boost::system::error_code ErrorCode;
        Scenario.ClientControl->close(ErrorCode);
        EXPECT_FALSE(ErrorCode);
    }
}
