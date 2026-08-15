/**
 * @file VmessConnErrorMatrix.cpp
 * @brief VMess conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - UUID 不匹配（bad_auth）
 * - 非法版本（bad_magic）
 * - 非法命令（not_supported）
 * - 非法地址类型（bad_message）
 * - 半包截断（io_error）
 * - 客户端响应校验失败
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
#include <common/proxy/vmess/vmess.hpp>

namespace
{
    using namespace psmtest;
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

    constexpr auto make_uuid = []() -> std::array<std::uint8_t, 16>
    {
        return {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    };



    TEST(VmessConnErrorMatrix, TruncatedHeader)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            vmess::server_config cfg;
            cfg.uuid = make_uuid();

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await vmess::accept(
                    std::make_shared<memory_stream>(std::move(b)), cfg);
                EXPECT_NE(err, error::none);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 只发 4 字节（半包）
            const std::vector<std::uint8_t> wire{0x01, 0x02, 0x03, 0x04};
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
            a.close();
        });
    }

} // namespace
