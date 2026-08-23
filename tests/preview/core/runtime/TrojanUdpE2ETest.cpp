/**
 * @file TrojanUdpE2ETest.cpp
 * @brief Trojan UDP_ASSOCIATE 纵向测试（链 P：数据面经 adapter 接入缝）
 * @details Trojan UDP 命令经 adapter::make_accept_trojan 置 is_dgram 并包装
 *          dgram 数据面；udp_service 在 dgram（TCP 承载）与真实 UDP 间中继。
 *          复用 runtime::session 的协议无关 dgram 分支。
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

#include <common/core/fault/code.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/adapter/protocol_adapter.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/trojan/dgram.hpp>
#include <common/protocols/trojan/trojan.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using udp = net::ip::udp;
    using tcp = net::ip::tcp;
    using namespace preview;
    using preview::runtime::make_accept_trojan;

    // 公共样板（run_coro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::run_coro;
    using psm::testing::udp_echo_server;

    /// Trojan 纵向测试共享状态
    struct trojan_udp_state
    {
        net::any_io_executor executor;
        std::uint16_t echo_port{0};
        /// 服务端数据面退出次数（TCP 关闭/空闲超时终止的证据）
        std::shared_ptr<std::atomic<int>> relay_exits{std::make_shared<std::atomic<int>>(0)};
    };

    /// 数据面单方向中继：客户端帧 ↔ 真实 UDP（echo 上游）
    auto udp_relay_frames(std::shared_ptr<preview::trojan::dgram<>> dgram,
                          std::uint16_t echo_port) -> net::awaitable<preview::fault::code>
    {
        udp::socket sock(dgram->executor());
        boost::system::error_code ec;
        sock.open(udp::v4(), ec);
        sock.bind(udp::endpoint(udp::v4(), 0), ec);
        if (ec)
        {
            co_return preview::fault::code::io_error;
        }
        while (true)
        {
            preview::trojan::address src;
            std::vector<std::uint8_t> payload;
            const auto rerr = co_await dgram->async_receive_from(src, payload);
            if (rerr != preview::error::none)
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
            std::array<std::byte, 65535> rx{};
            udp::endpoint from;
            const auto n = co_await sock.async_receive_from(
                net::buffer(rx), from, net::redirect_error(net::use_awaitable, ec));
            if (ec || n == 0)
            {
                break;
            }
            co_await dgram->async_send_to(
                src, std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(rx.data()), n));
        }
        co_return preview::fault::code::success;
    }

    /// 构造 Trojan UDP 数据面服务（dgram ↔ 真实 UDP 中继到 echo）
    auto make_trojan_udp_service(const std::shared_ptr<trojan_udp_state> &st,
                                 std::chrono::milliseconds idle_timeout)
        -> std::function<net::awaitable<preview::fault::code>(preview::middleware::context &)>
    {
        return [st, idle_timeout](preview::middleware::context &ctx)
            -> net::awaitable<preview::fault::code>
        {
            auto dgram = std::dynamic_pointer_cast<preview::trojan::dgram<>>(ctx.inbound);
            if (!dgram)
            {
                co_return preview::fault::code::protocol_error;
            }
            auto relay = [&]() -> net::awaitable<preview::fault::code>
            {
                co_return co_await udp_relay_frames(dgram, st->echo_port);
            };
            auto idle = [dgram, idle_timeout]() -> net::awaitable<preview::fault::code>
            {
                net::steady_timer timer(dgram->executor(), idle_timeout);
                co_await timer.async_wait(net::use_awaitable);
                dgram->close();
                co_return preview::fault::code::success;
            };
            using net::experimental::awaitable_operators::operator||;
            co_await (relay() || idle());
            ++(*st->relay_exits); // 数据面退出证据（TCP 断开或空闲超时）
            co_return preview::fault::code::success;
        };
    }

    TEST(TcpListener, TrojanUdpAssociateEcho)
    {
        net::io_context ioc;
        udp::endpoint echo_ep(udp::v4(), 0);
        udp::socket echo_sock(ioc.get_executor(), echo_ep);
        const auto echo_port = echo_sock.local_endpoint().port();
        auto echo_ep_ptr = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), udp_echo_server(std::move(echo_sock)),
                      [echo_ep_ptr](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *echo_ep_ptr = ep;
                          }
                      });

        auto state = std::make_shared<trojan_udp_state>(
            trojan_udp_state{ioc.get_executor(), echo_port});

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                preview::trojan::server_config scfg;
                scfg.password = "secret";
                scfg.enable_udp = true;
                opts.accept_protocol = make_accept_trojan(scfg);
                opts.udp_service = make_trojan_udp_service(state, std::chrono::seconds(5));
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool ok = false;
        std::string echo;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(
                    tcp::endpoint(tcp::v4(), 0));
                EXPECT_EQ(start_rc, fault::code::success);
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, dgram] = co_await preview::trojan::connect_packet(
                    std::move(raw), preview::trojan::client_config{"secret"},
                    preview::trojan::address{preview::trojan::address_type::domain,
                                             "example.com", 443});
                if (err != preview::error::none || !dgram)
                {
                    co_return;
                }
                const std::string payload = "trojan udp payload";
                co_await dgram->async_send_to(
                    preview::trojan::address{preview::trojan::address_type::domain,
                                             "example.com", 443},
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(payload.data()),
                        payload.size()));
                preview::trojan::address src;
                std::vector<std::uint8_t> rx;
                // 看门狗竞速：数据面断裂时失败而非挂死
                net::steady_timer wd(dgram->executor());
                wd.expires_after(std::chrono::seconds(2));
                using net::experimental::awaitable_operators::operator||;
                auto result = co_await (dgram->async_receive_from(src, rx) ||
                                        wd.async_wait(net::use_awaitable));
                const auto rerr = result.index() == 1 ? preview::error::timeout
                                                      : std::get<0>(std::move(result));
                if (rerr == preview::error::none)
                {
                    echo.assign(reinterpret_cast<const char *>(rx.data()), rx.size());
                    ok = (echo == payload);
                }
                dgram->close();
                listener.stop();
            });
        EXPECT_TRUE(ok);
        EXPECT_EQ(echo, "trojan udp payload");
        EXPECT_FALSE(*echo_ep_ptr);
    }

    TEST(TcpListener, TrojanUdpAssociateIdleTimeout)
    {
        net::io_context ioc;
        udp::endpoint echo_ep(udp::v4(), 0);
        udp::socket echo_sock(ioc.get_executor(), echo_ep);
        const auto echo_port = echo_sock.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), udp_echo_server(std::move(echo_sock)),
                      [](const std::exception_ptr &) {});

        auto state = std::make_shared<trojan_udp_state>(
            trojan_udp_state{ioc.get_executor(), echo_port});

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                preview::trojan::server_config scfg;
                scfg.password = "secret";
                scfg.enable_udp = true;
                opts.accept_protocol = make_accept_trojan(scfg);
                opts.udp_service = make_trojan_udp_service(state, std::chrono::milliseconds(150));
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool closed = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(
                    tcp::endpoint(tcp::v4(), 0));
                EXPECT_EQ(start_rc, fault::code::success);
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, dgram] = co_await preview::trojan::connect_packet(
                    std::move(raw), preview::trojan::client_config{"secret"},
                    preview::trojan::address{preview::trojan::address_type::domain,
                                             "example.com", 443});
                if (err != preview::error::none || !dgram)
                {
                    co_return;
                }
                // 不发数据，等待空闲超时
                net::steady_timer timer(ioc.get_executor(), std::chrono::milliseconds(400));
                co_await timer.async_wait(net::use_awaitable);
                preview::trojan::address src;
                std::vector<std::uint8_t> rx;
                const auto rerr = co_await dgram->async_receive_from(src, rx);
                closed = (rerr != preview::error::none);
                dgram->close();
                listener.stop();
            });
        EXPECT_TRUE(closed);
    }

    TEST(TcpListener, TrojanUdpAssociateTcpCloseTerminates)
    {
        net::io_context ioc;
        udp::endpoint echo_ep(udp::v4(), 0);
        udp::socket echo_sock(ioc.get_executor(), echo_ep);
        const auto echo_port = echo_sock.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), udp_echo_server(std::move(echo_sock)),
                      [](const std::exception_ptr &) {});

        auto state = std::make_shared<trojan_udp_state>(
            trojan_udp_state{ioc.get_executor(), echo_port});

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                preview::trojan::server_config scfg;
                scfg.password = "secret";
                scfg.enable_udp = true;
                opts.accept_protocol = make_accept_trojan(scfg);
                opts.udp_service = make_trojan_udp_service(state, std::chrono::seconds(30));
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool closed = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(
                    tcp::endpoint(tcp::v4(), 0));
                EXPECT_EQ(start_rc, fault::code::success);
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, dgram] = co_await preview::trojan::connect_packet(
                    std::move(raw), preview::trojan::client_config{"secret"},
                    preview::trojan::address{preview::trojan::address_type::domain,
                                             "example.com", 443});
                if (err != preview::error::none || !dgram)
                {
                    co_return;
                }
                // 先完成一次回包往返，确保服务端数据面已进入中继循环
                const std::string probe = "tcp-close probe";
                co_await dgram->async_send_to(
                    preview::trojan::address{preview::trojan::address_type::domain,
                                             "example.com", 443},
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(probe.data()), probe.size()));
                preview::trojan::address psrc;
                std::vector<std::uint8_t> prx;
                const auto perr = co_await dgram->async_receive_from(psrc, prx);
                if (perr != preview::error::none)
                {
                    ADD_FAILURE() << "probe roundtrip failed: " << (int)perr;
                    listener.stop();
                    co_return;
                }

                // 关闭 TCP 控制连接：服务端数据面必须在有界时间内终止
                dgram->close();
                net::steady_timer wd(ioc.get_executor());
                const auto deadline = std::chrono::steady_clock::now() +
                                      std::chrono::seconds(2);
                while (state->relay_exits->load(std::memory_order_acquire) == 0)
                {
                    if (std::chrono::steady_clock::now() > deadline)
                    {
                        throw std::runtime_error("udp data plane not terminated after tcp close");
                    }
                    wd.expires_after(std::chrono::milliseconds(5));
                    co_await wd.async_wait(net::use_awaitable);
                }
                closed = true;
                listener.stop();
            });
        EXPECT_TRUE(closed);
    }

} // namespace
