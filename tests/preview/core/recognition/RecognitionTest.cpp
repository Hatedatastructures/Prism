/**
 * @file RecognitionTest.cpp
 * @brief 协议识别流水线测试（T2-4）
 * @details 覆盖：
 *          - 协议首字节检测矩阵（socks5/tls/vless/trojan/vmess/http/unknown）
 *          - Probe 预读 + 回注
 *          - SNI 路由表（精确/通配/未命中）
 *          - Pipeline 完整识别（含预读回注可重读）
 */

#include <common/Core/Memory/Container.hpp>
#include <common/Core/Recognition/Recognition.hpp>
#include <common/Core/Recognition/Probe.hpp>
#include <common/Core/Recognition/Protocol.hpp>
#include <common/Core/Recognition/Route.hpp>
#include <common/Core/Transport/MemoryStream.hpp>

#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdint>
#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace rec = Preview::Recognition;
    using namespace Preview;

    /// 构造首包字节
    auto bytes_of(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return {List};
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
    EXPECT_EQ(rec::Detect(bytes_of({0x05})), rec::ProtocolType::socks5);
}

TEST(RecognitionProtocol, TlsDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0x16, 0x03})), rec::ProtocolType::tls);
    EXPECT_EQ(rec::Detect(bytes_of({0x16, 0x01})), rec::ProtocolType::unknown);
}

TEST(RecognitionProtocol, VlessDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0x56, 0x4C, 0x45, 0x53, 0x53})), rec::ProtocolType::vless);
    EXPECT_EQ(rec::Detect(bytes_of({0x56, 0x4C})), rec::ProtocolType::unknown);
    // 结构化识别：version 0x00 + addnl_len 0 + cmd Tcp + atyp domain
    std::vector<std::uint8_t> wire = {
        0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // version + uuid
        0x00,             // addnl_len
        0x01,             // cmd Tcp
        0x00, 0x50,       // port 80
        0x02,             // atyp domain
    };
    EXPECT_EQ(rec::Detect(wire), rec::ProtocolType::vless);
    // cmd 非法 → 不识别
    auto bad = wire;
    bad[18] = 0x09;
    EXPECT_EQ(rec::Detect(bad), rec::ProtocolType::unknown);
    // cmd=0x7f（mux）不在结构化识别白名单：mux 会话首包不可与 Tcp/udp
    // 区分数据面，识别层保守拒绝，由魔数/协议层自行处理
    auto mux_cmd = wire;
    mux_cmd[18] = 0x7f;
    EXPECT_EQ(rec::Detect(mux_cmd), rec::ProtocolType::unknown);
    // addnl_len 非零 → 不识别
    auto bad2 = wire;
    bad2[17] = 0x01;
    EXPECT_EQ(rec::Detect(bad2), rec::ProtocolType::unknown);
    // atyp 非法 → 不识别
    auto bad3 = wire;
    bad3[21] = 0x09;
    EXPECT_EQ(rec::Detect(bad3), rec::ProtocolType::unknown);
    // 不足 22 字节 → 不识别
    EXPECT_EQ(rec::Detect(bytes_of({0x00, 1, 2, 3})), rec::ProtocolType::unknown);
    // 21 字节（边界下沿）→ 不识别
    std::vector<std::uint8_t> boundary(21, 0x00);
    boundary[0] = 0x00;
    boundary[17] = 0x00;
    boundary[18] = 0x01;
    boundary[21 - 1] = 0x01;
    EXPECT_EQ(rec::Detect(boundary), rec::ProtocolType::unknown);
}

TEST(RecognitionProtocol, TrojanDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0x0D, 0x0A, 0x0D, 0x0A})), rec::ProtocolType::trojan);
}

TEST(RecognitionProtocol, VmessDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0x01})), rec::ProtocolType::vmess);
}

TEST(RecognitionProtocol, HttpDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({'G', 'E', 'T', ' '})), rec::ProtocolType::http);
    EXPECT_EQ(rec::Detect(bytes_of({'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '})), rec::ProtocolType::http);
}

TEST(RecognitionProtocol, UnknownDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0xAA, 0xBB})), rec::ProtocolType::unknown);
    EXPECT_EQ(rec::Detect({}), rec::ProtocolType::unknown);
}

// ── Probe ──

TEST(RecognitionProbe, ProbeAndRewind)
{
    net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 // 写入 TLS 首包
                 std::array<std::byte, 4> tls{std::byte{0x16}, std::byte{0x03}, std::byte{0x01}, std::byte{0x00}};
                 std::error_code ec;
                 co_await sb->AsyncWriteSome(tls, ec);

                 auto probe_res = co_await rec::Probe(*sa);
                 EXPECT_EQ(probe_res.Type, rec::ProtocolType::tls);
                 EXPECT_EQ(probe_res.PreReadSize, 4u);

                 // 回注后仍可读完整数据
                 auto rewound = rec::WrapPreread(sa, std::span<const std::byte>(probe_res.pre_read.data(),
                                                                                 probe_res.PreReadSize));
                 std::array<std::byte, 8> buf{};
                 const auto n = co_await rewound->AsyncReadSome(buf, ec);
                 EXPECT_EQ(n, 4u);
                 EXPECT_EQ(buf[0], std::byte{0x16});
             });
}

// ── SNI 路由表 ──

TEST(RecognitionRoute, ExactMatch)
{
    rec::SniRouteTable routes;
    routes.Add("example.com", "reality");
    EXPECT_EQ(routes.Lookup("example.com"), "reality");
    EXPECT_EQ(routes.Lookup("other.com"), "");
}

TEST(RecognitionRoute, WildcardMatch)
{
    rec::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("sub.example.com"), "shadowtls");
    EXPECT_EQ(routes.Lookup("example.com"), ""); // 通配不含根域
    EXPECT_EQ(routes.Lookup("other.example.com"), "shadowtls");
}

TEST(RecognitionRoute, MultipleRoutes)
{
    rec::SniRouteTable routes;
    routes.Add("a.com", "reality");
    routes.Add("b.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("a.com"), "reality");
    EXPECT_EQ(routes.Lookup("b.com"), "shadowtls");
    EXPECT_EQ(routes.Size(), 2u);
    routes.Clear();
    EXPECT_EQ(routes.Size(), 0u);
}

// ── Pipeline ──

TEST(RecognitionPipeline, DetectAndRewind)
{
    net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    rec::Pipeline pipe;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 std::array<std::byte, 5> vless{std::byte{0x56}, std::byte{0x4C}, std::byte{0x45},
                                                std::byte{0x53}, std::byte{0x53}};
                 std::error_code ec;
                 co_await sb->AsyncWriteSome(vless, ec);

                 auto Result = co_await pipe.Recognize(sa);
                 EXPECT_TRUE(Result.success);
                 EXPECT_EQ(Result.detected, rec::ProtocolType::vless);
                 EXPECT_EQ(Result.preread.size(), 5u);

                 // 回注后可读完整 vless 头
                 std::array<std::byte, 8> buf{};
                 const auto n = co_await Result.transport->AsyncReadSome(buf, ec);
                 EXPECT_EQ(n, 5u);
             });
}

TEST(RecognitionPipeline, UnknownPassthrough)
{
    net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    rec::Pipeline pipe;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 std::array<std::byte, 3> unknown{std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
                 std::error_code ec;
                 co_await sb->AsyncWriteSome(unknown, ec);

                 auto Result = co_await pipe.Recognize(sa);
                 EXPECT_FALSE(Result.success);
                 // 预读数据回注（unknown 也回注，保持数据完整）
                 EXPECT_GE(Result.preread.size(), 1u);
             });
}
