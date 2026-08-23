/**
 * @file Ss2022ConnErrorMatrix.cpp
 * @brief Shadowsocks 2022 conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - 密码不匹配（PSK 派生差异 → AEAD 解密失败 → bad_auth）
 * - 半包截断（salt 未收满 → io_error）
 * @note 客户端连接失败后由服务端关闭底层流解除读阻塞。
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
#include <common/protocols/shadowsocks2022/shadowsocks2022.hpp>

namespace
{
    using namespace preview;
    namespace net = boost::asio;
    namespace ss = preview::shadowsocks2022;

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

    TEST(Ss2022ConnErrorMatrix, BadPassword)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端正确密码，客户端错误密码
            shadowsocks2022::server_config srv_cfg;
            srv_cfg.password = "server-correct";
            auto b_stream = std::make_shared<memory_stream>(std::move(b));

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await shadowsocks2022::accept(b_stream, srv_cfg);
                EXPECT_EQ(err, error::bad_auth); // 错误密码 → 固定头解密失败
                b_stream->close();           // 解除客户端响应读取阻塞（EOF）
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 客户端用错误密码握手：首包正常发送，但响应校验失败
            shadowsocks2022::client_config ccfg;
            ccfg.password = "client-wrong";
            auto [err, conn] = co_await shadowsocks2022::connect(
                std::make_shared<memory_stream>(std::move(a)), ccfg,
                ss::address{ss::address_type::domain, "t.internal", 443});
            // 客户端侧：错误密码 → 服务端静默断开（bad_auth 后不写响应）→ 读响应 EOF
            EXPECT_EQ(err, error::io_error);
        });
    }

    TEST(Ss2022ConnErrorMatrix, TruncatedHeader)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            shadowsocks2022::server_config cfg;
            cfg.password = "server-secret";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] =
                    co_await shadowsocks2022::accept(std::make_shared<memory_stream>(std::move(b)), cfg);
                EXPECT_EQ(err, error::io_error); // 半包后 EOF
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 只发 4 字节（salt 未收满）后关闭
            const std::vector<std::uint8_t> wire{0x01, 0x02, 0x03, 0x04};
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
            a.close();
        });
    }

} // namespace
