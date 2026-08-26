/**
 * @file SS2022UdpE2ETest.cpp
 * @brief Shadowsocks2022 UDP 直连测试（独立数据报通道）
 * @details 服务端统一 Bind 端口 0 后回读实际端口，避免 ctest 并行冲突；
 *          所有接收操作与看门狗定时器竞速，回归时失败而非挂死。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

namespace
{
    namespace net = boost::asio;
    using namespace boost::asio::experimental::awaitable_operators;
    using namespace Preview;

    /// 接收看门狗超时（超过即判定挂死）
    constexpr auto kRecvDeadline = std::chrono::milliseconds(2000);

    /**
     * @brief 与看门狗竞速的接收：返回 nullopt 表示超时（测试应判失败）
     */
    auto RecvGuarded(const Shadowsocks2022::SharedDgram &sock, Shadowsocks2022::Address &src,
                      std::vector<std::uint8_t> &Rx)
        -> net::awaitable<std::optional<Error>>
    {
        net::steady_timer wd(sock->Executor());
        wd.expires_after(kRecvDeadline);
        auto Result = co_await (sock->AsyncReceiveFrom(src, Rx) ||
                                wd.async_wait(net::use_awaitable));
        if (Result.index() == 1)
        {
            co_return std::nullopt; // 超时
        }
        co_return std::get<0>(std::move(Result));
    }

    /// 创建绑定随机端口的服务端并回读端点
    auto MakeServer(net::io_context &ioc, const char *password)
        -> std::pair<Shadowsocks2022::SharedDgram, net::ip::udp::endpoint>
    {
        net::ip::udp::endpoint bound;
        auto Server = Shadowsocks2022::AcceptPacket(
            ioc.get_executor(), 0, Shadowsocks2022::ServerConfig{password}, &bound);
        return {std::move(Server), bound};
    }

    TEST(SS2022Udp, DirectEchoDomain)
    {
        net::io_context ioc;
        bool Ok = false;
        std::exception_ptr done_ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto [Server, bound] = MakeServer(ioc, "Secret");
            if (!Server) { ADD_FAILURE() << "Server null"; co_return; }
            const auto remote = "127.0.0.1:" + std::to_string(bound.port());
            auto Client = Shadowsocks2022::ConnectPacket(
                ioc.get_executor(), remote, Shadowsocks2022::ClientConfig{"Secret"});
            if (!Client) { ADD_FAILURE() << "Client null"; co_return; }

            const std::string payload = "ss2022 udp payload";
            Shadowsocks2022::Address dst{Shadowsocks2022::AddressType::Domain, "example.com", 443};
            auto serr = co_await Client->AsyncSendTo(
                dst, std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
            if (serr != Error::None) { ADD_FAILURE() << (int)serr; co_return; }

            Shadowsocks2022::Address src;
            std::vector<std::uint8_t> Rx;
            const auto rerr = co_await RecvGuarded(Server, src, Rx);
            if (rerr != Error::None) { ADD_FAILURE() << "recv1: " << (rerr ? (int)*rerr : -1); co_return; }
            const std::string got(reinterpret_cast<const char *>(Rx.data()), Rx.size());
            if (got != payload) { ADD_FAILURE() << got; co_return; }

            auto serr2 = co_await Server->AsyncSendTo(
                src, std::span<const std::uint8_t>(Rx.data(), Rx.size()));
            if (serr2 != Error::None) { ADD_FAILURE() << (int)serr2; co_return; }

            Shadowsocks2022::Address src2;
            std::vector<std::uint8_t> rx2;
            const auto rerr2 = co_await RecvGuarded(Client, src2, rx2);
            if (rerr2 != Error::None) { ADD_FAILURE() << "recv2: " << (rerr2 ? (int)*rerr2 : -1); co_return; }
            const std::string echo(reinterpret_cast<const char *>(rx2.data()), rx2.size());
            Ok = (echo == payload);
        }, [&](std::exception_ptr ep) { done_ep = ep; ioc.stop(); });
        ioc.run();
        if (done_ep)
        {
            std::rethrow_exception(done_ep);
        }
        EXPECT_TRUE(Ok);
    }

    TEST(SS2022Udp, DirectEchoIpv4)
    {
        net::io_context ioc;
        bool Ok = false;
        std::exception_ptr done_ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto [Server, bound] = MakeServer(ioc, "Secret");
            if (!Server) { ADD_FAILURE() << "Server null"; co_return; }
            const auto remote = "127.0.0.1:" + std::to_string(bound.port());
            auto Client = Shadowsocks2022::ConnectPacket(
                ioc.get_executor(), remote, Shadowsocks2022::ClientConfig{"Secret"});
            if (!Client) { ADD_FAILURE() << "Client null"; co_return; }

            const std::string payload = "ipv4 payload";
            Shadowsocks2022::Address dst{Shadowsocks2022::AddressType::Ipv4, "1.2.3.4", 80};
            auto serr = co_await Client->AsyncSendTo(
                dst, std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
            if (serr != Error::None) { ADD_FAILURE() << (int)serr; co_return; }
            Shadowsocks2022::Address src;
            std::vector<std::uint8_t> Rx;
            const auto rerr = co_await RecvGuarded(Server, src, Rx);
            if (rerr != Error::None) { ADD_FAILURE() << "recv: " << (rerr ? (int)*rerr : -1); co_return; }
            Ok = (std::string(reinterpret_cast<const char *>(Rx.data()), Rx.size()) == payload);
        }, [&](std::exception_ptr ep) { done_ep = ep; ioc.stop(); });
        ioc.run();
        if (done_ep)
        {
            std::rethrow_exception(done_ep);
        }
        EXPECT_TRUE(Ok);
    }

    TEST(SS2022Udp, BadPskDrop)
    {
        net::io_context ioc;
        bool rejected = false;
        std::exception_ptr done_ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto [Server, bound] = MakeServer(ioc, "right");
            if (!Server) { ADD_FAILURE() << "Server null"; co_return; }
            const auto remote = "127.0.0.1:" + std::to_string(bound.port());
            auto Client = Shadowsocks2022::ConnectPacket(
                ioc.get_executor(), remote, Shadowsocks2022::ClientConfig{"wrong"});
            if (!Client) { ADD_FAILURE() << "Client null"; co_return; }

            const std::string payload = "bad psk";
            Shadowsocks2022::Address dst{Shadowsocks2022::AddressType::Domain, "example.com", 443};
            auto serr = co_await Client->AsyncSendTo(
                dst, std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
            if (serr != Error::None) { ADD_FAILURE() << (int)serr; co_return; }

            // 错误 PSK 包必须被拒绝：SessionID 校验失败 → bad_auth，且不产出可读回包。
            // Dgram 为无状态逐包解析，坏包以错误码上浮（对齐 Codec ParseUdpPacket 契约）
            Shadowsocks2022::Address src;
            std::vector<std::uint8_t> Rx;
            const auto rerr = co_await RecvGuarded(Server, src, Rx);
            if (rerr != Error::BadAuth)
            {
                ADD_FAILURE() << "expected bad_auth, got "
                              << (rerr ? (int)*rerr : -1);
                co_return;
            }
            // 关闭后接收应以错误收口而非挂死
            Server->Close();
            const auto cerr2 = co_await Server->AsyncReceiveFrom(src, Rx);
            rejected = (cerr2 != Error::None);
        }, [&](std::exception_ptr ep) { done_ep = ep; ioc.stop(); });
        ioc.run();
        if (done_ep)
        {
            std::rethrow_exception(done_ep);
        }
        EXPECT_TRUE(rejected);
    }
}
