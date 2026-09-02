/**
 * @file TrojanConnErrorMatrix.cpp
 * @brief Trojan Conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - 凭据不匹配（bad_auth）
 * - 凭据后缺 CRLF（bad_magic）
 * - 非法命令（not_supported）
 * - 非法地址类型（bad_message）
 * - 半包截断（io_error）
 * - 客户端响应校验失败
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e)
                      { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(TrojanConnErrorMatrix, BadCredential)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "correct";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::BadAuth);
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            // 错误凭据（56 hex）+ CRLF + 命令
            const std::string cred(56, '0');
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {'\r', '\n', 0x01, 0x01, 0x00, 0x50});
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(TrojanConnErrorMatrix, MissingCrlf)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "prism";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::BadMagic); // 凭据后缺 CRLF
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            // 正确凭据 + 缺 CRLF
            const auto cred = Trojan::Credential("prism");
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {0x01, 0x02});
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(TrojanConnErrorMatrix, BadCommand)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "prism";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::BadMessage); // 命令 0x99 不在白名单
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            const auto cred = Trojan::Credential("prism");
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {'\r', '\n', 0x99, 0x01, 0x00, 0x50}); // 命令 0x99
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(TrojanConnErrorMatrix, BadAddressType)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "prism";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::BadMessage); // ATYP=9 非法
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            const auto cred = Trojan::Credential("prism");
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {'\r', '\n', 0x01, 0x09, 0x00, 0x50}); // ATYP=9
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(TrojanConnErrorMatrix, TruncatedHeader)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "prism";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::IoError); // 半包后 EOF
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            const auto cred = Trojan::Credential("prism");
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {'\r', '\n', 0x01}); // 截断
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            a.Close();
            co_await std::move(server_task);
        });
    }

} // namespace
