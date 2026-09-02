/**
 * @file VMessUdpE2ETest.cpp
 * @brief VMess UDP 纵向测试（链 P：数据面经 adapter 接入缝）
 * @details VMess UDP 命令经 adapter::MakeAcceptVmess 置 is_dgram 并包装
 *          Dgram 数据面；udp_service 在 Dgram（AEAD 承载）与真实 UDP 间中继。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <preview/Runtime/Listener.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Vmess/Dgram.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using udp = net::ip::udp;
    using Tcp = net::ip::tcp;
    using namespace Preview;
    using Preview::Runtime::MakeAcceptVmess;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::MakeUuid;
    using Preview::Testing::RunCoro;
    using Preview::Testing::UdpEchoServer;

    /// 测试 UUID 兼容别名
    inline auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        return MakeUuid();
    }

    /// VMess UDP 纵向测试共享状态
    struct vmess_udp_state
    {
        net::any_io_executor Executor;
        std::uint16_t echo_port{0};
        /// 服务端数据面退出次数（TCP 关闭/空闲超时终止的证据）
        std::shared_ptr<std::atomic<int>> relay_exits{std::make_shared<std::atomic<int>>(0)};
    };

    /// 数据面单方向中继：客户端帧 ↔ 真实 UDP（echo 上游）
    auto udp_relay_frames(std::shared_ptr<Preview::Vmess::Dgram<>> Dgram,
                          std::uint16_t echo_port) -> net::awaitable<Preview::Fault::Code>
    {
        udp::socket sock(Dgram->Executor());
        boost::system::error_code ec;
        sock.open(net::ip::udp::v4(), ec);
        sock.bind(udp::endpoint(udp::v4(), 0), ec);
        if (ec)
        {
            co_return Preview::Fault::Code::IoError;
        }
        while (true)
        {
            std::vector<std::uint8_t> payload;
            const auto rerr = co_await Dgram->AsyncReceiveFrom(payload);
            if (rerr != Preview::Error::None)
            {
                break;
            }
            const udp::endpoint ep(net::ip::make_address("127.0.0.1"), echo_port);
            co_await sock.async_send_to(net::buffer(payload), ep,
                                        net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                break;
            }
            std::array<std::byte, 65535> Rx{};
            udp::endpoint from;
            const auto n = co_await sock.async_receive_from(
                net::buffer(Rx), from, net::redirect_error(net::use_awaitable, ec));
            if (ec || n == 0)
            {
                break;
            }
            co_await Dgram->AsyncSendTo(
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(Rx.data()), n));
        }
        co_return Preview::Fault::Code::Success;
    }

    /// 构造 VMess UDP 数据面服务（Dgram ↔ 真实 UDP 中继到 echo）
    auto make_vmess_udp_service(const std::shared_ptr<vmess_udp_state> &st,
                                std::chrono::milliseconds idle_timeout)
        -> std::function<net::awaitable<Preview::Fault::Code>(Preview::Middleware::Context &)>
    {
        return [st, idle_timeout](Preview::Middleware::Context &ctx)
            -> net::awaitable<Preview::Fault::Code>
        {
            auto Dgram = std::dynamic_pointer_cast<Preview::Vmess::Dgram<>>(ctx.Inbound);
            if (!Dgram)
            {
                co_return Preview::Fault::Code::ProtocolError;
            }
            auto relay = [&]() -> net::awaitable<Preview::Fault::Code>
            {
                co_return co_await udp_relay_frames(Dgram, st->echo_port);
            };
            auto idle = [Dgram, idle_timeout]() -> net::awaitable<Preview::Fault::Code>
            {
                net::steady_timer timer(Dgram->Executor(), idle_timeout);
                co_await timer.async_wait(net::use_awaitable);
                Dgram->Close();
                co_return Preview::Fault::Code::Success;
            };
            using net::experimental::awaitable_operators::operator||;
            co_await (relay() || idle());
            ++(*st->relay_exits); // 数据面退出证据（TCP 断开或空闲超时）
            co_return Preview::Fault::Code::Success;
        };
    }

    TEST(TcpListener, VmessUdpConnectEcho)
    {
        net::io_context ioc;
        udp::endpoint echo_ep(udp::v4(), 0);
        udp::socket echo_sock(ioc.get_executor(), echo_ep);
        const auto echo_port = echo_sock.local_endpoint().port();
        auto echo_ep_ptr = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), Preview::Testing::UdpEchoServer(std::move(echo_sock)),
                      [echo_ep_ptr](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *echo_ep_ptr = ep;
                          }
                      });

        auto State = std::make_shared<vmess_udp_state>(
            vmess_udp_state{ioc.get_executor(), echo_port});

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptVmess(
                    Vmess::ServerConfig{test_uuid()});
                opts.udp_service = make_vmess_udp_service(State, std::chrono::seconds(5));
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool Ok = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::Success);
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                // VMess UDP：先用 ConnectPacket 握手得到 Dgram
                auto [err, Dgram] = co_await Vmess::ConnectPacket(
                    std::move(raw), Vmess::ClientConfig{test_uuid()},
                    Vmess::Address{Vmess::AddressType::Domain, "example.com", 443});
                if (err != Error::None || !Dgram)
                {
                    co_return;
                }
                const std::string payload = "vmess udp payload";
                co_await Dgram->AsyncSendTo(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
                std::vector<std::uint8_t> Rx;
                // 看门狗竞速：数据面断裂时失败而非挂死
                net::steady_timer wd(Dgram->Executor());
                wd.expires_after(std::chrono::seconds(2));
                using net::experimental::awaitable_operators::operator||;
                auto Result =
                    co_await (Dgram->AsyncReceiveFrom(Rx) || wd.async_wait(net::use_awaitable));
                const auto rerr = Result.index() == 1 ? Error::Timeout
                                                      : std::get<0>(std::move(Result));
                if (rerr == Error::None)
                {
                    const std::string echo(reinterpret_cast<const char *>(Rx.data()), Rx.size());
                    Ok = (echo == payload);
                }
                Dgram->Close();
                listener.Stop();
            });
        EXPECT_TRUE(Ok);
        EXPECT_FALSE(*echo_ep_ptr);
    }

    TEST(TcpListener, VmessUdpConnectIdleTimeout)
    {
        net::io_context ioc;
        udp::endpoint echo_ep(udp::v4(), 0);
        udp::socket echo_sock(ioc.get_executor(), echo_ep);
        const auto echo_port = echo_sock.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), Preview::Testing::UdpEchoServer(std::move(echo_sock)),
                      [](const std::exception_ptr &) {});

        auto State = std::make_shared<vmess_udp_state>(
            vmess_udp_state{ioc.get_executor(), echo_port});

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptVmess(
                    Vmess::ServerConfig{test_uuid()});
                opts.udp_service = make_vmess_udp_service(State, std::chrono::milliseconds(150));
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool closed = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::Success);
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, Dgram] = co_await Vmess::ConnectPacket(
                    std::move(raw), Vmess::ClientConfig{test_uuid()},
                    Vmess::Address{Vmess::AddressType::Domain, "example.com", 443});
                if (err != Error::None || !Dgram)
                {
                    co_return;
                }
                net::steady_timer timer(ioc.get_executor(), std::chrono::milliseconds(400));
                co_await timer.async_wait(net::use_awaitable);
                std::vector<std::uint8_t> Rx;
                const auto rerr = co_await Dgram->AsyncReceiveFrom(Rx);
                closed = (rerr != Error::None);
                Dgram->Close();
                listener.Stop();
            });
        EXPECT_TRUE(closed);
    }

    TEST(TcpListener, VmessUdpConnectTcpCloseTerminates)
    {
        net::io_context ioc;
        udp::endpoint echo_ep(udp::v4(), 0);
        udp::socket echo_sock(ioc.get_executor(), echo_ep);
        const auto echo_port = echo_sock.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), Preview::Testing::UdpEchoServer(std::move(echo_sock)),
                      [](const std::exception_ptr &) {});

        auto State = std::make_shared<vmess_udp_state>(
            vmess_udp_state{ioc.get_executor(), echo_port});

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptVmess(
                    Vmess::ServerConfig{test_uuid()});
                opts.udp_service = make_vmess_udp_service(State, std::chrono::seconds(30));
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool closed = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::Success);
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, Dgram] = co_await Vmess::ConnectPacket(
                    std::move(raw), Vmess::ClientConfig{test_uuid()},
                    Vmess::Address{Vmess::AddressType::Domain, "example.com", 443});
                if (err != Error::None || !Dgram)
                {
                    co_return;
                }
                // 先完成一次回包往返，确保服务端数据面已进入中继循环
                const std::string Probe = "Tcp-Close Probe";
                co_await Dgram->AsyncSendTo(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(Probe.data()), Probe.size()));
                std::vector<std::uint8_t> prx;
                const auto perr = co_await Dgram->AsyncReceiveFrom(prx);
                if (perr != Error::None)
                {
                    ADD_FAILURE() << "Probe roundtrip Failed: " << (int)perr;
                    listener.Stop();
                    co_return;
                }

                // 关闭 TCP 控制连接：服务端数据面必须在有界时间内终止
                Dgram->Close();
                net::steady_timer wd(ioc.get_executor());
                const auto deadline = std::chrono::steady_clock::now() +
                                      std::chrono::seconds(2);
                while (State->relay_exits->load(std::memory_order_acquire) == 0)
                {
                    if (std::chrono::steady_clock::now() > deadline)
                    {
                        throw std::runtime_error("udp Data plane not terminated after Tcp Close");
                    }
                    wd.expires_after(std::chrono::milliseconds(5));
                    co_await wd.async_wait(net::use_awaitable);
                }
                closed = true;
                listener.Stop();
            });
        EXPECT_TRUE(closed);
    }

} // namespace
