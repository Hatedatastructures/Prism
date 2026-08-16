/**
 * @file RecognitionTest.cpp
 * @brief 协议识别流水线测试（T2-4）
 * @details 覆盖：
 *          - 协议首字节检测矩阵（socks5/tls/vless/trojan/vmess/http/unknown）
 *          - probe 预读 + 回注
 *          - SNI 路由表（精确/通配/未命中）
 *          - pipeline 完整识别（含预读回注可重读）
 */

#include <common/core/memory/container.hpp>
#include <common/core/recognition/recognition.hpp>
#include <common/core/recognition/probe.hpp>
#include <common/core/recognition/protocol.hpp>
#include <common/core/recognition/route.hpp>
#include <common/core/transport/memory_stream.hpp>

#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdint>
#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace rec = psmtest::recognition;
    using namespace psmtest;

    /// 构造首包字节
    auto bytes_of(std::initializer_list<std::uint8_t> list) -> std::vector<std::uint8_t>
    {
        return {list};
    }

    template <typename A>
    void run_coro(net::io_context &ioc, A coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }
} // namespace

// ── 协议检测矩阵 ──

TEST(RecognitionProtocol, Socks5Detect)
{
    EXPECT_EQ(rec::detect(bytes_of({0x05})), rec::protocol_type::socks5);
}

TEST(RecognitionProtocol, TlsDetect)
{
    EXPECT_EQ(rec::detect(bytes_of({0x16, 0x03})), rec::protocol_type::tls);
    EXPECT_EQ(rec::detect(bytes_of({0x16, 0x01})), rec::protocol_type::unknown);
}

TEST(RecognitionProtocol, VlessDetect)
{
    EXPECT_EQ(rec::detect(bytes_of({0x56, 0x4C, 0x45, 0x53, 0x53})), rec::protocol_type::vless);
    EXPECT_EQ(rec::detect(bytes_of({0x56, 0x4C})), rec::protocol_type::unknown);
}

TEST(RecognitionProtocol, TrojanDetect)
{
    EXPECT_EQ(rec::detect(bytes_of({0x0D, 0x0A, 0x0D, 0x0A})), rec::protocol_type::trojan);
}

TEST(RecognitionProtocol, VmessDetect)
{
    EXPECT_EQ(rec::detect(bytes_of({0x01})), rec::protocol_type::vmess);
}

TEST(RecognitionProtocol, HttpDetect)
{
    EXPECT_EQ(rec::detect(bytes_of({'G', 'E', 'T', ' '})), rec::protocol_type::http);
    EXPECT_EQ(rec::detect(bytes_of({'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '})), rec::protocol_type::http);
}

TEST(RecognitionProtocol, UnknownDetect)
{
    EXPECT_EQ(rec::detect(bytes_of({0xAA, 0xBB})), rec::protocol_type::unknown);
    EXPECT_EQ(rec::detect({}), rec::protocol_type::unknown);
}

// ── probe ──

TEST(RecognitionProbe, ProbeAndRewind)
{
    net::io_context ioc;
    auto [a, b] = make_memory_pair(ioc.get_executor());
    auto sa = std::make_shared<psmtest::memory_stream>(std::move(a));
    auto sb = std::make_shared<psmtest::memory_stream>(std::move(b));

    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 // 写入 TLS 首包
                 std::array<std::byte, 4> tls{std::byte{0x16}, std::byte{0x03}, std::byte{0x01}, std::byte{0x00}};
                 std::error_code ec;
                 co_await sb->async_write_some(tls, ec);

                 auto probe_res = co_await rec::probe(*sa);
                 EXPECT_EQ(probe_res.type, rec::protocol_type::tls);
                 EXPECT_EQ(probe_res.pre_read_size, 4u);

                 // 回注后仍可读完整数据
                 auto rewound = rec::wrap_preread(sa, std::span<const std::byte>(probe_res.pre_read.data(),
                                                                                 probe_res.pre_read_size));
                 std::array<std::byte, 8> buf{};
                 const auto n = co_await rewound->async_read_some(buf, ec);
                 EXPECT_EQ(n, 4u);
                 EXPECT_EQ(buf[0], std::byte{0x16});
             });
}

// ── SNI 路由表 ──

TEST(RecognitionRoute, ExactMatch)
{
    rec::route_table routes;
    routes.add("example.com", "reality");
    EXPECT_EQ(routes.lookup("example.com"), "reality");
    EXPECT_EQ(routes.lookup("other.com"), "");
}

TEST(RecognitionRoute, WildcardMatch)
{
    rec::route_table routes;
    routes.add("*.example.com", "shadowtls");
    EXPECT_EQ(routes.lookup("sub.example.com"), "shadowtls");
    EXPECT_EQ(routes.lookup("example.com"), ""); // 通配不含根域
    EXPECT_EQ(routes.lookup("other.example.com"), "shadowtls");
}

TEST(RecognitionRoute, MultipleRoutes)
{
    rec::route_table routes;
    routes.add("a.com", "reality");
    routes.add("b.com", "shadowtls");
    EXPECT_EQ(routes.lookup("a.com"), "reality");
    EXPECT_EQ(routes.lookup("b.com"), "shadowtls");
    EXPECT_EQ(routes.size(), 2u);
    routes.clear();
    EXPECT_EQ(routes.size(), 0u);
}

// ── pipeline ──

TEST(RecognitionPipeline, DetectAndRewind)
{
    net::io_context ioc;
    auto [a, b] = make_memory_pair(ioc.get_executor());
    auto sa = std::make_shared<psmtest::memory_stream>(std::move(a));
    auto sb = std::make_shared<psmtest::memory_stream>(std::move(b));

    rec::pipeline pipe;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 std::array<std::byte, 5> vless{std::byte{0x56}, std::byte{0x4C}, std::byte{0x45},
                                                std::byte{0x53}, std::byte{0x53}};
                 std::error_code ec;
                 co_await sb->async_write_some(vless, ec);

                 auto result = co_await pipe.recognize(sa);
                 EXPECT_TRUE(result.success);
                 EXPECT_EQ(result.detected, rec::protocol_type::vless);
                 EXPECT_EQ(result.preread.size(), 5u);

                 // 回注后可读完整 vless 头
                 std::array<std::byte, 8> buf{};
                 const auto n = co_await result.transport->async_read_some(buf, ec);
                 EXPECT_EQ(n, 5u);
             });
}

TEST(RecognitionPipeline, UnknownPassthrough)
{
    net::io_context ioc;
    auto [a, b] = make_memory_pair(ioc.get_executor());
    auto sa = std::make_shared<psmtest::memory_stream>(std::move(a));
    auto sb = std::make_shared<psmtest::memory_stream>(std::move(b));

    rec::pipeline pipe;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 std::array<std::byte, 3> unknown{std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
                 std::error_code ec;
                 co_await sb->async_write_some(unknown, ec);

                 auto result = co_await pipe.recognize(sa);
                 EXPECT_FALSE(result.success);
                 // 预读数据回注（unknown 也回注，保持数据完整）
                 EXPECT_GE(result.preread.size(), 1u);
             });
}
