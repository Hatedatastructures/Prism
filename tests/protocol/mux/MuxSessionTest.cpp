/**
 * @file MuxSessionTest.cpp
 * @brief 多路复用会话测试（smux / yamux / h2mux 独立实现）
 * @details 覆盖：open/accept、双向数据传输、多流并发、FIN 关闭语义。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/mux/smux/smux.hpp>
#include <common/mux/yamux/yamux.hpp>
#include <common/mux/h2mux/h2mux.hpp>

namespace
{
    using namespace psmtest;
    using namespace psmtest::mux;

    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e)
                      { ep = e; if (e) ioc.stop(); });
        ioc.run();
        if (ep)
            std::rethrow_exception(ep);
    }

    /// 通用会话测试：cl/sv 为 (client, server) 对象，payload 回显
    template <typename Client, typename Server>
    auto run_session(net::io_context &ioc, Client &cl, Server &sv,
                     const std::size_t payload_size) -> std::size_t
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto csess = cl.connect(std::make_shared<memory_stream>(std::move(a)));
        auto ssess = sv.accept(std::make_shared<memory_stream>(std::move(b)));

        std::size_t received = 0;
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto s = co_await ssess->accept_stream();
                if (!s)
                {
                    EXPECT_TRUE(false) << "accept failed";
                    co_return;
                }
                std::array<std::uint8_t, 64 * 1024> buf{};
                while (true)
                {
                    const auto n = co_await s->read_some(buf);
                    if (n == 0)
                        break;
                    received += n;
                    (void)co_await s->write_all(
                        std::span<const std::uint8_t>(buf.data(), n));
                }
                co_await s->close();
            };
            net::co_spawn(ssess->executor(), server_coro(), net::detached);

            auto s = co_await csess->open_stream();
            if (!s)
            {
                EXPECT_TRUE(false) << "open failed";
                co_return;
            }
            std::string payload(payload_size, 'M');
            (void)co_await s->write_all(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
            std::string echoed;
            std::array<std::uint8_t, 64 * 1024> buf{};
            while (echoed.size() < payload.size())
            {
                const auto n = co_await s->read_some(buf);
                if (n == 0)
                    break;
                echoed.append(reinterpret_cast<const char *>(buf.data()), n);
            }
            EXPECT_EQ(echoed, payload);
            co_await s->close();
            co_await csess->close();
            co_await ssess->close(); });
        return received;
    }

    TEST(MuxSession, SmuxEcho)
    {
        net::io_context ioc;
        smux::client cl(session_options{});
        smux::server sv(session_options{});
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, YamuxEcho)
    {
        net::io_context ioc;
        yamux::client cl(session_options{});
        yamux::server sv(session_options{});
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, H2muxEcho)
    {
        net::io_context ioc;
        h2mux::client cl(session_options{});
        h2mux::server sv(session_options{});
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, SmuxMultiStream)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        smux::client cl(session_options{});
        smux::server sv(session_options{});
        auto csess = cl.connect(std::make_shared<memory_stream>(std::move(a)));
        auto ssess = sv.accept(std::make_shared<memory_stream>(std::move(b)));

        constexpr int kStreams = 8;
        constexpr std::size_t kPayload = 64 * 1024;
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                std::array<std::uint8_t, 4096> buf{};
                for (int i = 0; i < kStreams; ++i)
                {
                    auto s = co_await ssess->accept_stream();
                    if (!s)
                        continue;
                    std::size_t got = 0;
                    while (got < kPayload)
                    {
                        const auto n = co_await s->read_some(buf);
                        if (n == 0)
                            break;
                        got += n;
                    }
                    EXPECT_EQ(got, kPayload);
                    co_await s->close();
                }
            };
            net::co_spawn(ssess->executor(), server_coro(), net::detached);

            std::string payload(kPayload, 'C');
            for (int i = 0; i < kStreams; ++i)
            {
                auto s = co_await csess->open_stream();
                if (!s)
                    continue;
                (void)co_await s->write_all(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
                co_await s->close();
            }
            co_await csess->close();
            co_await ssess->close(); });
    }

    TEST(MuxSession, FactorySmux)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        smux::client cl(session_options{});
        smux::server sv(session_options{});
        auto csess = cl.connect(std::make_shared<memory_stream>(std::move(a)));
        auto ssess = sv.accept(std::make_shared<memory_stream>(std::move(b)));
        ASSERT_NE(csess, nullptr);
        ASSERT_NE(ssess, nullptr);
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto s = co_await ssess->accept_stream();
                if (!s)
                    co_return;
                std::array<std::uint8_t, 4096> buf{};
                while (true)
                {
                    const auto n = co_await s->read_some(buf);
                    if (n == 0)
                        break;
                }
            };
            net::co_spawn(ssess->executor(), server_coro(), net::detached);
            auto s = co_await csess->open_stream();
            if (!s)
                co_return;
            const std::string payload = "factory smux";
            (void)co_await s->write_all(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
            co_await s->close();
            co_await csess->close();
            co_await ssess->close(); });
    }

} // namespace
