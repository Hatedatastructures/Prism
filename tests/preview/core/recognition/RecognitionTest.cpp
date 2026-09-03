/**
 * @file RecognitionTest.cpp
 * @brief 协议识别流水线测试（T2-4）
 * @details 覆盖：
 *          - 协议首字节检测矩阵（socks5/tls/vless/trojan/vmess/http/unknown）
 *          - Probe 预读 + 回注
 *          - SNI 路由表（精确/通配/未命中）
 *          - Pipeline 完整识别（含预读回注可重读）
 */

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Runtime/Recognition/Recognition.hpp>
#include <preview/Runtime/Recognition/Probe.hpp>
#include <preview/Runtime/Recognition/Protocol.hpp>
#include <preview/Runtime/Recognition/Route.hpp>
#include <preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <preview/Runtime/Recognition/Tls.hpp>
#include <preview/Transport/MemoryStream.hpp>

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
    EXPECT_EQ(rec::Detect(bytes_of({0x05})), rec::ProtocolType::Socks5);
}

TEST(RecognitionProtocol, TlsDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0x16, 0x03})), rec::ProtocolType::Tls);
    EXPECT_EQ(rec::Detect(bytes_of({0x16, 0x01})), rec::ProtocolType::Unknown);
}

TEST(RecognitionProtocol, VlessDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0x56, 0x4C, 0x45, 0x53, 0x53})), rec::ProtocolType::Vless);
    EXPECT_EQ(rec::Detect(bytes_of({0x56, 0x4C})), rec::ProtocolType::Unknown);
    // 结构化识别：version 0x00 + AddnlLen 0 + cmd Tcp + atyp domain
    std::vector<std::uint8_t> wire = {
        0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // version + uuid
        0x00,             // AddnlLen
        0x01,             // cmd Tcp
        0x00, 0x50,       // port 80
        0x02,             // atyp domain
    };
    EXPECT_EQ(rec::Detect(wire), rec::ProtocolType::Vless);
    // cmd 非法 → 不识别
    auto bad = wire;
    bad[18] = 0x09;
    EXPECT_EQ(rec::Detect(bad), rec::ProtocolType::Unknown);
    // cmd=0x7f（mux）不在结构化识别白名单：mux 会话首包不可与 Tcp/udp
    // 区分数据面，识别层保守拒绝，由魔数/协议层自行处理
    auto mux_cmd = wire;
    mux_cmd[18] = 0x7f;
    EXPECT_EQ(rec::Detect(mux_cmd), rec::ProtocolType::Unknown);
    // AddnlLen 非零 → 不识别
    auto bad2 = wire;
    bad2[17] = 0x01;
    EXPECT_EQ(rec::Detect(bad2), rec::ProtocolType::Unknown);
    // atyp 非法 → 不识别
    auto bad3 = wire;
    bad3[21] = 0x09;
    EXPECT_EQ(rec::Detect(bad3), rec::ProtocolType::Unknown);
    // 不足 22 字节 → 不识别
    EXPECT_EQ(rec::Detect(bytes_of({0x00, 1, 2, 3})), rec::ProtocolType::Unknown);
    // 21 字节（边界下沿）→ 不识别
    std::vector<std::uint8_t> boundary(21, 0x00);
    boundary[0] = 0x00;
    boundary[17] = 0x00;
    boundary[18] = 0x01;
    boundary[21 - 1] = 0x01;
    EXPECT_EQ(rec::Detect(boundary), rec::ProtocolType::Unknown);
}

TEST(RecognitionProtocol, TrojanDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0x0D, 0x0A, 0x0D, 0x0A})), rec::ProtocolType::Trojan);
}

TEST(RecognitionProtocol, VmessDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0x01})), rec::ProtocolType::Vmess);
}

TEST(RecognitionProtocol, HttpDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({'G', 'E', 'T', ' '})), rec::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(bytes_of({'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '})), rec::ProtocolType::Http);
}

TEST(RecognitionProtocol, UnknownDetect)
{
    EXPECT_EQ(rec::Detect(bytes_of({0xAA, 0xBB})), rec::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect({}), rec::ProtocolType::Unknown);
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
                 co_await sb->async_write_some(tls, ec);

                 auto probe_res = co_await rec::Probe(*sa);
                 EXPECT_EQ(probe_res.Type, rec::ProtocolType::Tls);
                 EXPECT_EQ(probe_res.PreReadSize, 4u);

                 // 回注后仍可读完整数据
                 auto rewound = rec::WrapPreread(sa, std::span<const std::byte>(probe_res.PreRead.data(),
                                                                                 probe_res.PreReadSize));
                 std::array<std::byte, 8> buf{};
                 const auto n = co_await rewound->async_read_some(buf, ec);
                 EXPECT_EQ(n, 4u);
                 EXPECT_EQ(buf[0], std::byte{0x16});
             });
}

TEST(RecognitionProbe, ReadsUntilProtocolCanBeClassified)
{
    net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    net::co_spawn(
        ioc,
        [sb]() -> net::awaitable<void>
        {
            const std::array<std::byte, 4> tls{
                std::byte{0x16}, std::byte{0x03}, std::byte{0x01}, std::byte{0x00}};
            for (const auto Byte : tls)
            {
                std::error_code ec;
                const std::array<std::byte, 1> one{Byte};
                co_await sb->async_write_some(one, ec);
                co_await net::post(sb->Executor(), net::use_awaitable);
            }
        },
        net::detached);

    rec::ProbeResult result;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 result = co_await rec::Probe(*sa);
             });

    EXPECT_EQ(result.Type, rec::ProtocolType::Tls);
    EXPECT_GE(result.PreReadSize, 2U);
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

TEST(RecognitionRoute, LookupNormalizesAsciiCase)
{
    rec::SniRouteTable routes;
    routes.Add("Example.COM", "reality");
    EXPECT_EQ(routes.Lookup("example.com"), "reality");
}

TEST(RecognitionRoute, LongestWildcardWins)
{
    rec::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    routes.Add("*.deep.example.com", "reality");
    EXPECT_EQ(routes.Lookup("node.deep.example.com"), "reality");
}

TEST(RecognitionRoute, WildcardMatchesSingleLabelOnly)
{
    rec::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("a.b.example.com"), "");
}

TEST(RecognitionRoute, LookupEntryCarriesProtocolAndFallback)
{
    rec::SniRouteTable routes;
    routes.Add("api.example.com", "native", rec::ProtocolType::Vless, true);
    const auto *entry = routes.LookupEntry("API.EXAMPLE.COM.");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->Scheme, "native");
    EXPECT_EQ(entry->Protocol, rec::ProtocolType::Vless);
    EXPECT_TRUE(entry->AllowFallback);
}

TEST(RecognitionTls, ParsesClientHelloSniAndVersion)
{
    const auto PushU16 = [](std::vector<std::uint8_t> &out, const std::size_t value)
    {
        out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    };
    const auto PushU24 = [](std::vector<std::uint8_t> &out, const std::size_t value)
    {
        out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    };

    const std::string Host = "Example.COM";
    std::vector<std::uint8_t> Sni;
    PushU16(Sni, Host.size() + 3);
    Sni.push_back(0x00);
    PushU16(Sni, Host.size());
    Sni.insert(Sni.end(), Host.begin(), Host.end());

    std::vector<std::uint8_t> Extensions;
    PushU16(Extensions, 0x0000);
    PushU16(Extensions, Sni.size());
    Extensions.insert(Extensions.end(), Sni.begin(), Sni.end());
    PushU16(Extensions, 0x002B);
    PushU16(Extensions, 3);
    Extensions.push_back(2);
    PushU16(Extensions, 0x0304);

    std::vector<std::uint8_t> Body{0x03, 0x03};
    Body.insert(Body.end(), 32, 0x42);
    Body.push_back(0x00); // session_id length
    Body.push_back(0x00);
    Body.push_back(0x02); // one cipher suite
    Body.push_back(0x13);
    Body.push_back(0x01);
    Body.push_back(0x01); // one compression method
    Body.push_back(0x00);
    PushU16(Body, Extensions.size());
    Body.insert(Body.end(), Extensions.begin(), Extensions.end());

    std::vector<std::uint8_t> Record{0x16, 0x03, 0x01, 0x00, 0x00};
    Record[3] = static_cast<std::uint8_t>(((Body.size() + 4) >> 8) & 0xFF);
    Record[4] = static_cast<std::uint8_t>((Body.size() + 4) & 0xFF);
    Record.push_back(0x01);
    PushU24(Record, Body.size());
    Record.insert(Record.end(), Body.begin(), Body.end());

    const auto [Err, Features] = rec::ParseClientHello(Record);
    EXPECT_EQ(Err, Error::None);
    EXPECT_EQ(Features.ServerName, Host);
    EXPECT_EQ(Features.LegacyVersion, 0x0303);
    ASSERT_EQ(Features.Versions.size(), 1u);
    EXPECT_EQ(Features.Versions.front(), 0x0304);
    EXPECT_EQ(Features.RawRecord.size(), Record.size());
}

TEST(RecognitionTls, ReadsRecordAfterPrereadPrefix)
{
    net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));
    const std::array<std::uint8_t, 9> Record{
        0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};
    const std::array<std::byte, 2> Prefix{
        static_cast<std::byte>(Record[0]), static_cast<std::byte>(Record[1])};

    net::co_spawn(
        ioc,
        [sb, Record]() -> net::awaitable<void>
        {
            std::error_code ec;
            co_await sb->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Record.data() + 2), 7), ec);
        },
        net::detached);

    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 const auto [Err, Got] = co_await rec::ReadTlsRecord(*sa, Prefix);
                 EXPECT_EQ(Err, Error::None);
                 EXPECT_EQ(Got.size(), Record.size());
                 if (Got.size() != Record.size())
                 {
                     co_return;
                 }
                 EXPECT_TRUE(std::equal(Got.begin(), Got.end(), Record.begin(), Record.end()));
             });
}

TEST(RecognitionTls, RejectsNonHandshakeAndTruncatedRecords)
{
    const std::array<std::uint8_t, 5> ApplicationData{
        0x17, 0x03, 0x03, 0x00, 0x00};
    const auto [ApplicationError, unusedApplication] = rec::ParseClientHello(ApplicationData);
    (void)unusedApplication;
    EXPECT_EQ(ApplicationError, Error::BadMessage);

    const std::array<std::uint8_t, 9> Truncated{
        0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};
    const auto [TruncatedError, unusedTruncated] = rec::ParseClientHello(Truncated);
    (void)unusedTruncated;
    EXPECT_EQ(TruncatedError, Error::BadMessage);
}

TEST(RecognitionPipeline, RoutesTlsClientHelloToScheme)
{
    const auto PushU16 = [](std::vector<std::uint8_t> &out, const std::size_t value)
    {
        out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    };
    const auto PushU24 = [](std::vector<std::uint8_t> &out, const std::size_t value)
    {
        out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    };
    const std::string Host = "example.com";
    std::vector<std::uint8_t> Sni;
    PushU16(Sni, Host.size() + 3);
    Sni.push_back(0x00);
    PushU16(Sni, Host.size());
    Sni.insert(Sni.end(), Host.begin(), Host.end());
    std::vector<std::uint8_t> Extensions;
    PushU16(Extensions, 0x0000);
    PushU16(Extensions, Sni.size());
    Extensions.insert(Extensions.end(), Sni.begin(), Sni.end());
    std::vector<std::uint8_t> Body{0x03, 0x03};
    Body.insert(Body.end(), 32, 0x42);
    Body.push_back(0x00);
    Body.push_back(0x00);
    Body.push_back(0x02);
    Body.push_back(0x13);
    Body.push_back(0x01);
    Body.push_back(0x01);
    Body.push_back(0x00);
    PushU16(Body, Extensions.size());
    Body.insert(Body.end(), Extensions.begin(), Extensions.end());
    std::vector<std::uint8_t> Record{0x16, 0x03, 0x01, 0x00, 0x00, 0x01};
    Record[3] = static_cast<std::uint8_t>(((Body.size() + 4) >> 8) & 0xFF);
    Record[4] = static_cast<std::uint8_t>((Body.size() + 4) & 0xFF);
    PushU24(Record, Body.size());
    Record.insert(Record.end(), Body.begin(), Body.end());

    net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));
    rec::SniRouteTable routes;
    routes.Add("example.com", "reality", rec::ProtocolType::Trojan);
    rec::SchemeExecutor executor;
    auto called = std::make_shared<bool>(false);
    executor.RegisterScheme("reality", [called](SharedTransmission Inbound)
                            -> net::awaitable<SharedTransmission>
    {
        *called = true;
        co_return Inbound;
    });
    rec::Pipeline pipe(&routes, &executor);

    run_coro(ioc,
             [sa, sb, Record, Pipe = &pipe, called]() -> net::awaitable<void>
             {
                 std::error_code ec;
                 co_await sb->async_write_some(
                     std::span<const std::byte>(reinterpret_cast<const std::byte *>(Record.data()), Record.size()), ec);
                 auto Result = co_await Pipe->Recognize(sa);
                 EXPECT_TRUE(Result.success);
                 EXPECT_EQ(Result.detected, rec::ProtocolType::Trojan);
                 EXPECT_EQ(Result.scheme, "reality");
                 EXPECT_TRUE(*called);
                 std::array<std::byte, 5> replay{};
                 const auto N = co_await Result.transport->async_read_some(replay, ec);
                 EXPECT_EQ(N, replay.size());
                 EXPECT_EQ(replay[0], std::byte{0x16});
             });
}

TEST(RecognitionPipeline, RejectsUnknownTlsSni)
{
    const std::vector<std::uint8_t> Record{
        0x16, 0x03, 0x01, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24,
        0x03, 0x03, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x00, 0x00, 0x02, 0x13, 0x01,
        0x01, 0x00};
    net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));
    rec::SniRouteTable routes;
    routes.Add("known.example", "reality", rec::ProtocolType::Trojan);
    rec::SchemeExecutor executor;
    rec::Pipeline pipe(&routes, &executor);

    run_coro(ioc,
             [sa, sb, Record, Pipe = &pipe]() -> net::awaitable<void>
             {
                 std::error_code ec;
                 co_await sb->async_write_some(
                     std::span<const std::byte>(reinterpret_cast<const std::byte *>(Record.data()), Record.size()), ec);
                 auto Result = co_await Pipe->Recognize(sa);
                 EXPECT_FALSE(Result.success);
                 EXPECT_EQ(Result.detected, rec::ProtocolType::Tls);
                 EXPECT_TRUE(Result.scheme.empty());
             });
}

TEST(RecognitionPipeline, RewindsTransportWhenSchemeFails)
{
    const std::vector<std::uint8_t> Sni{
        0x00, 0x0E, 0x00, 0x00, 0x00, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    std::vector<std::uint8_t> Extensions{0x00, 0x00, 0x00, 0x10};
    Extensions.insert(Extensions.end(), Sni.begin(), Sni.end());
    std::vector<std::uint8_t> Body{0x03, 0x03};
    Body.insert(Body.end(), 32, 0x42);
    Body.insert(Body.end(), {0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00,
                             0x00, 0x14});
    Body.insert(Body.end(), Extensions.begin(), Extensions.end());
    std::vector<std::uint8_t> Record{
        0x16, 0x03, 0x01, 0x00, static_cast<std::uint8_t>(Body.size() + 4),
        0x01, 0x00, static_cast<std::uint8_t>((Body.size() >> 16) & 0xFF),
        static_cast<std::uint8_t>((Body.size() >> 8) & 0xFF),
        static_cast<std::uint8_t>(Body.size() & 0xFF)};
    Record.insert(Record.end(), Body.begin(), Body.end());
    net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));
    rec::SniRouteTable routes;
    routes.Add("example.com", "reject", rec::ProtocolType::Trojan);
    rec::SchemeExecutor executor;
    executor.RegisterScheme("reject", [](SharedTransmission) -> net::awaitable<SharedTransmission>
                            { co_return nullptr; });
    rec::Pipeline pipe(&routes, &executor);

    run_coro(ioc,
             [sa, sb, Record, Pipe = &pipe]() -> net::awaitable<void>
             {
                 std::error_code ec;
                 co_await sb->async_write_some(
                     std::span<const std::byte>(reinterpret_cast<const std::byte *>(Record.data()), Record.size()), ec);
                 auto Result = co_await Pipe->Recognize(sa);
                 EXPECT_FALSE(Result.success);
                 EXPECT_NE(Result.transport, nullptr);
                 if (!Result.transport)
                 {
                     co_return;
                 }
                 std::array<std::byte, 5> Replayed{};
                 const auto Read = co_await Result.transport->async_read_some(Replayed, ec);
                 EXPECT_EQ(Read, Replayed.size());
                 EXPECT_EQ(Replayed[0], std::byte{0x16});
             });
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
                 co_await sb->async_write_some(vless, ec);

                 auto Result = co_await pipe.Recognize(sa);
                 EXPECT_TRUE(Result.success);
                 EXPECT_EQ(Result.detected, rec::ProtocolType::Vless);
                 EXPECT_EQ(Result.preread.size(), 5u);

                 // 回注后可读完整 vless 头
                 std::array<std::byte, 8> buf{};
                 const auto n = co_await Result.transport->async_read_some(buf, ec);
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
                 co_await sb->async_write_some(unknown, ec);
                 sb->Close();

                 auto Result = co_await pipe.Recognize(sa);
                 EXPECT_FALSE(Result.success);
                 // 预读数据回注（unknown 也回注，保持数据完整）
                 EXPECT_GE(Result.preread.size(), 1u);
             });
}
