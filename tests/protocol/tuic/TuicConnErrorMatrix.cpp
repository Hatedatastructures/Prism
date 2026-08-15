/**
 * @file TuicConnErrorMatrix.cpp
 * @brief Tuic conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - 半包截断（帧头/地址体未收满 → unexpected_eof）
 * - 正常握手基线（connect/accept 成功）
 * @note psmtest::tuic 握手为简化实现（不做 UUID/密码认证），
 *       故无 BadCredential 用例。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/tuic/tuic.hpp>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /**
     * @brief 生成测试 UUID（全 0x55）
     */
    auto make_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> u{};
        u.fill(0x55);
        return u;
    }

    TEST(TuicConnErrorMatrix, TruncatedHeader)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            tuic::server_config cfg;
            cfg.uuid = make_uuid();
            cfg.password = "pw";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] =
                    co_await tuic::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                EXPECT_NE(err, error::none); // 半包后 EOF → unexpected_eof
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 只发 Ver + Cmd（缺地址体）后关闭
            const std::vector<std::uint8_t> wire{tuic::protocol_version, tuic::cmd_connect};
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
            a.close();
        });
    }

    TEST(TuicConnErrorMatrix, HandshakeOk)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端完成信号（确保服务端 EXPECT 已求值）
            net::experimental::channel<void(boost::system::error_code)> done(ioc.get_executor(), 1);

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await tuic::accept(
                    std::make_shared<memory_stream>(std::move(b)),
                    tuic::server_config{make_uuid(), "pw"});
                EXPECT_EQ(err, error::none);
                EXPECT_EQ(req.cmd, tuic::cmd_connect);
                EXPECT_EQ(req.dst.host, "t.internal");
                EXPECT_EQ(req.dst.port, 443u);
                co_await done.async_send(boost::system::error_code{}, net::use_awaitable);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            tuic::client_config cfg;
            cfg.uuid = make_uuid();
            cfg.password = "pw";
            auto [err, conn] = co_await tuic::connect(
                std::make_shared<memory_stream>(std::move(a)), cfg,
                tuic::address{tuic::address_type::domain, "t.internal", 443});
            EXPECT_EQ(err, error::none);
            EXPECT_NE(conn, nullptr);
            co_await done.async_receive(net::use_awaitable);
        });
    }

} // namespace
