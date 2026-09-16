/**
 * @file RecognitionTest.cpp
 * @brief 协议识别流水线测试（T2-4）
 * @details 覆盖：
 *          - 协议首字节检测矩阵（socks5/tls/vless/trojan/vmess/http/unknown）
 *          - Probe 预读 + 回注
 *          - SNI 路由表（精确/通配/未命中）
 *          - Pipeline 完整识别（含预读回注可重读）
 */

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Runtime/Recognition/Probe.hpp>
#include <Preview/Runtime/Recognition/Protocol.hpp>
#include <Preview/Runtime/Recognition/Route.hpp>
#include <Preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include "RecognitionWire.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <concepts>
#include <memory>
#include <string_view>
#include <stdexcept>
#include <thread>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace rec = Preview::Recognition;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;

    /// 构造首包字节
    auto BytesOf(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return {List};
    }

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr ErrorValue)
                      { Exception = ErrorValue; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto WaitForRecognitionEvent(Net::any_io_executor Executor, std::chrono::milliseconds Delay,
                                 rec::RecognitionControlEvent Event)
        -> Net::awaitable<rec::RecognitionControlEvent>
    {
        Net::steady_timer Timer(Executor);
        Timer.expires_after(Delay);
        co_await Timer.async_wait(Net::use_awaitable);
        co_return Event;
    }
} // namespace

// ── 协议检测矩阵 ──

TEST(RecognitionProtocol, Socks5Detect)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x05})), rec::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect(BytesOf({0x05, 0x01})), rec::ProtocolType::Socks5);
    EXPECT_EQ(rec::Detect(BytesOf({0x05, 0x10})), rec::ProtocolType::Socks5);
    EXPECT_EQ(rec::Detect(BytesOf({0x05, 0x00})), rec::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect(BytesOf({0x05, 0x11})), rec::ProtocolType::Unknown);
    EXPECT_TRUE(rec::CouldBeProtocolPrefix(BytesOf({0x05})));
    EXPECT_FALSE(rec::CouldBeProtocolPrefix(BytesOf({0x05, 0x00})));
    EXPECT_FALSE(rec::CouldBeProtocolPrefix(BytesOf({0x05, 0x11})));
}

TEST(RecognitionProtocol, TlsDetect)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x16, 0x03})), rec::ProtocolType::Tls);
    EXPECT_EQ(rec::Detect(BytesOf({0x16, 0x01})), rec::ProtocolType::Unknown);
}

template <typename T>
concept HasRecognitionStatusString = requires(T Value)
{
    { rec::ToStringView(Value) } -> std::same_as<std::string_view>;
};

template <typename T>
auto ExpectRecognitionStatusStrings() -> void
{
    EXPECT_TRUE(HasRecognitionStatusString<T>);
    if constexpr (HasRecognitionStatusString<T>)
    {
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::Accepted)), "accepted");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::NoMatch)), "no_match");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::Ambiguous)), "ambiguous");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::BudgetExceeded)), "budget_exceeded");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::TimedOut)), "timed_out");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::EndOfStream)), "end_of_stream");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::IoError)), "io_error");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::Polluted)), "polluted");
    }
}

TEST(RecognitionStatus, HasStableDiagnosticStrings)
{
    ExpectRecognitionStatusStrings<rec::RecognitionStatus>();
}

TEST(RecognitionProtocol, VlessDetect)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x56, 0x4C, 0x45, 0x53, 0x53})), rec::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect(BytesOf({0x56, 0x4C})), rec::ProtocolType::Unknown);
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
    EXPECT_EQ(rec::Detect(BytesOf({0x00, 1, 2, 3})), rec::ProtocolType::Unknown);
    // 21 字节（边界下沿）→ 不识别
    std::vector<std::uint8_t> boundary(21, 0x00);
    boundary[0] = 0x00;
    boundary[17] = 0x00;
    boundary[18] = 0x01;
    boundary[21 - 1] = 0x01;
    EXPECT_EQ(rec::Detect(boundary), rec::ProtocolType::Unknown);
}

TEST(RecognitionProtocol, TrojanDetectDoesNotGuessCrlfPrefix)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x0D, 0x0A, 0x0D, 0x0A})), rec::ProtocolType::Unknown);
    EXPECT_FALSE(rec::CouldBeProtocolPrefix(BytesOf({0x0D, 0x0A, 0x0D, 0x0A})));
}

TEST(RecognitionProtocol, VmessDetectDoesNotGuessRandomPrefix)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x01})), rec::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect(BytesOf({0x01, 0x00, 0x00, 0x00, 0x00, 0x42})),
              rec::ProtocolType::Unknown);
}

TEST(RecognitionProtocol, HttpDetect)
{
    EXPECT_EQ(rec::Detect(BytesOf({'G', 'E', 'T', ' '})), rec::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(BytesOf({'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '})), rec::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(BytesOf({'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '})), rec::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(BytesOf({'T', 'R', 'A', 'C', 'E', ' '})), rec::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(BytesOf({'P', 'A', 'T', 'C', 'H', ' '})), rec::ProtocolType::Http);
}

TEST(RecognitionProtocol, UnknownDetect)
{
    EXPECT_EQ(rec::Detect(BytesOf({0xAA, 0xBB})), rec::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect({}), rec::ProtocolType::Unknown);
}

// ── Probe ──

TEST(RecognitionProbe, ProbeAndRewind)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
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
                 std::array<std::byte, 22> buf{};
                 const auto n = co_await rewound->async_read_some(buf, ec);
                 EXPECT_EQ(n, 4u);
                 EXPECT_EQ(buf[0], std::byte{0x16});
             });
}

TEST(RecognitionProbe, ReadsUntilProtocolCanBeClassified)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    Net::co_spawn(
        ioc,
        [sb]() -> Net::awaitable<void>
        {
            const std::array<std::byte, 4> tls{
                std::byte{0x16}, std::byte{0x03}, std::byte{0x01}, std::byte{0x00}};
            for (const auto Byte : tls)
            {
                std::error_code ec;
                const std::array<std::byte, 1> one{Byte};
                co_await sb->async_write_some(one, ec);
                co_await Net::post(sb->Executor(), Net::use_awaitable);
            }
        },
        Net::detached);

    rec::ProbeResult result;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 result = co_await rec::Probe(*sa);
             });

    EXPECT_EQ(result.Type, rec::ProtocolType::Tls);
    EXPECT_GE(result.PreReadSize, 2U);
}

TEST(RecognitionProbe, ReadsFragmentedSocks5GreetingBeforeClassification)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    Net::co_spawn(
        ioc,
        [sb]() -> Net::awaitable<void>
        {
            std::error_code ec;
            const std::array<std::byte, 1> Version{std::byte{0x05}};
            co_await sb->async_write_some(Version, ec);
            co_await Net::post(sb->Executor(), Net::use_awaitable);
            const std::array<std::byte, 1> MethodCount{std::byte{0x01}};
            co_await sb->async_write_some(MethodCount, ec);
        },
        Net::detached);

    rec::ProbeResult result;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 result = co_await rec::Probe(*sa);
             });

    EXPECT_EQ(result.Type, rec::ProtocolType::Socks5);
    EXPECT_EQ(result.PreReadSize, 2U);
}

TEST(RecognitionProbe, ReadsFragmentedOptionsBeforeHttpClassification)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    Net::co_spawn(
        ioc,
        [sb]() -> Net::awaitable<void>
        {
            std::error_code ec;
            const std::array<std::byte, 3> Prefix{std::byte{'O'}, std::byte{'P'}, std::byte{'T'}};
            co_await sb->async_write_some(Prefix, ec);
            co_await Net::post(sb->Executor(), Net::use_awaitable);
            const std::array<std::byte, 5> Suffix{
                std::byte{'I'}, std::byte{'O'}, std::byte{'N'}, std::byte{'S'}, std::byte{' '}};
            co_await sb->async_write_some(Suffix, ec);
        },
        Net::detached);

    rec::ProbeResult result;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 result = co_await rec::Probe(*sa);
             });

    EXPECT_EQ(result.Type, rec::ProtocolType::Http);
    EXPECT_EQ(result.PreReadSize, 8U);
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
    routes.Add("api.example.com", "native", rec::RouteOptions{rec::ProtocolType::Vless, true});
    const auto entry = routes.LookupEntry("API.EXAMPLE.COM.");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->Scheme, "native");
    EXPECT_EQ(entry->Protocol, rec::ProtocolType::Vless);
    EXPECT_TRUE(entry->AllowFallback);
}

TEST(RecognitionRoute, LookupEntryReturnsOwnedValue)
{
    rec::SniRouteTable routes;
    routes.Add("example.com", "native");

    const auto entry = routes.LookupEntry("example.com");
    ASSERT_TRUE(entry.has_value());
    routes.Clear();

    EXPECT_EQ(entry->Scheme, "native");
}

TEST(RecognitionRoute, ConcurrentLookupAndMutationUsesStableSnapshots)
{
    rec::SniRouteTable routes;
    routes.Add("*.example.com", "initial");
    std::atomic<bool> failed{false};

    std::thread writer([&]
                       {
                           for (int I = 0; I < 500; ++I)
                           {
                               const char *CandidateName = "second";
                               if (I % 2 == 0)
                               {
                                   CandidateName = "first";
                               }
                               routes.Add("*.example.com", CandidateName);
                               routes.SetDefault(CandidateName);
                               if (I % 3 == 0)
                               {
                                   routes.ClearDefault();
                               }
                           }
                       });
    std::array<std::thread, 4> readers;
    for (auto &reader : readers)
    {
        reader = std::thread([&]
                             {
                                 for (int I = 0; I < 1000; ++I)
                                 {
                                     const auto Value = routes.LookupValue("node.example.com");
                                     if (Value && Value->Scheme != "initial" && Value->Scheme != "first" &&
                                         Value->Scheme != "second")
                                     {
                                         failed = true;
                                     }
                                 }
                             });
    }
    writer.join();
    for (auto &reader : readers)
    {
        reader.join();
    }

    EXPECT_FALSE(failed.load());
    EXPECT_EQ(routes.Size(), 1u);
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
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));
    const std::array<std::uint8_t, 9> Record{
        0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};
    const std::array<std::byte, 2> Prefix{
        static_cast<std::byte>(Record[0]), static_cast<std::byte>(Record[1])};

    Net::co_spawn(
        ioc,
        [sb, Record]() -> Net::awaitable<void>
        {
            std::error_code ec;
            co_await sb->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Record.data() + 2), 7), ec);
        },
        Net::detached);

    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
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

    auto InvalidRecordVersion = Preview::Testing::RecognitionWire::MakeTlsClientHello("invalid-version.example");
    InvalidRecordVersion[1] = std::byte{0x02};
    std::vector<std::uint8_t> InvalidVersionBytes;
    InvalidVersionBytes.reserve(InvalidRecordVersion.size());
    for (const auto Byte : InvalidRecordVersion)
    {
        InvalidVersionBytes.push_back(std::to_integer<std::uint8_t>(Byte));
    }
    const auto [VersionError, unusedVersion] = rec::ParseClientHello(InvalidVersionBytes);
    (void)unusedVersion;
    EXPECT_EQ(VersionError, Error::BadMessage);
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

    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));
    rec::SniRouteTable routes;
    routes.Add("example.com", "reality", rec::RouteOptions{rec::ProtocolType::Trojan, false});
    rec::SchemeExecutor executor;
    auto called = std::make_shared<bool>(false);
    executor.RegisterScheme("reality", [called](SharedTransmission Inbound)
                            -> Net::awaitable<SharedTransmission>
    {
        *called = true;
        co_return Inbound;
    });
    rec::Pipeline pipe(&routes, &executor);

    RunCoro(ioc,
             [sa, sb, Record, Pipe = &pipe, called]() -> Net::awaitable<void>
             {
                 std::error_code ec;
                 co_await sb->async_write_some(
                     std::span<const std::byte>(reinterpret_cast<const std::byte *>(Record.data()), Record.size()), ec);
                 auto Result = co_await Pipe->Recognize(sa);
                 EXPECT_TRUE(Result.success);
                 EXPECT_EQ(Result.preread.size(), Record.size());
                 EXPECT_EQ(Result.detected, rec::ProtocolType::Trojan);
                 EXPECT_EQ(Result.scheme, "reality");
                 EXPECT_TRUE(*called);
                 std::array<std::byte, 5> replay{};
                 const auto N = co_await Result.transport->async_read_some(replay, ec);
                 EXPECT_EQ(N, replay.size());
                 EXPECT_EQ(replay[0], std::byte{0x16});
             });
}

TEST(RecognitionPipeline, NormalizesSchemeCaseAcrossRouteAndExecutor)
{
    Net::io_context Io;
    auto [a, b] = MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(b));
    const auto Wire = Preview::Testing::RecognitionWire::MakeTlsClientHello("case.example");

    rec::SniRouteTable Routes;
    Routes.Add("case.example", "NATIVE", rec::RouteOptions{rec::ProtocolType::Tls, false});
    rec::SchemeExecutor Executor;
    Executor.RegisterScheme("native", [](SharedTransmission Inbound) -> Net::awaitable<SharedTransmission>
                            { co_return Inbound; });
    rec::Pipeline Pipeline(&Routes, &Executor);
    rec::RecognizeResult Result;

    RunCoro(Io, [Client, Peer, Wire, &Pipeline, &Result]() -> Net::awaitable<void>
              {
                  std::error_code Error;
                  co_await Peer->async_write_some(Wire, Error);
                  Result = co_await Pipeline.Recognize(Client);
              });

    EXPECT_TRUE(Result.success);
    EXPECT_EQ(Result.preread.size(), Wire.size());
    EXPECT_EQ(Result.scheme, "native");
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
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));
    rec::SniRouteTable routes;
    routes.Add("known.example", "reality", rec::RouteOptions{rec::ProtocolType::Trojan, false});
    rec::SchemeExecutor executor;
    rec::Pipeline pipe(&routes, &executor);

    RunCoro(ioc,
             [sa, sb, Record, Pipe = &pipe]() -> Net::awaitable<void>
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
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));
    rec::SniRouteTable routes;
    routes.Add("example.com", "reject", rec::RouteOptions{rec::ProtocolType::Trojan, false});
    rec::SchemeExecutor executor;
    executor.RegisterScheme("reject", [](SharedTransmission) -> Net::awaitable<SharedTransmission>
                            { co_return nullptr; });
    rec::Pipeline pipe(&routes, &executor);

    RunCoro(ioc,
             [sa, sb, Record, Pipe = &pipe]() -> Net::awaitable<void>
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

TEST(RecognitionPipeline, ConvertsSchemeExceptionToReplayableFailure)
{
    const auto Record = Preview::Testing::RecognitionWire::MakeTlsClientHello("example.com");
    Net::io_context Ioc;
    auto [a, b] = MakeMemoryPair(Ioc.get_executor());
    auto Client = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(b));
    rec::SniRouteTable Routes;
    Routes.Add("example.com", "throwing", rec::RouteOptions{rec::ProtocolType::Tls, false});
    rec::SchemeExecutor Executor;
    ASSERT_TRUE(Executor.RegisterScheme(
        "throwing", [](SharedTransmission) -> Net::awaitable<SharedTransmission>
        {
            throw std::runtime_error("scheme failure");
            co_return nullptr;
        }));
    rec::Pipeline Pipeline(&Routes, &Executor);
    rec::RecognizeResult Result;
    std::exception_ptr Failure;
    std::array<std::byte, 5> ReplayedPrefix{};
    std::size_t Replayed = 0;

    Net::co_spawn(
        Ioc,
        [Peer, Client, &Pipeline, &Result, &Ioc, &ReplayedPrefix, &Replayed, Record]() -> Net::awaitable<void>
        {
            std::error_code Error;
            co_await Peer->async_write_some(Record, Error);
            Result = co_await Pipeline.Recognize(Client);
            if (Result.transport)
            {
                Replayed = co_await Result.transport->async_read_some(ReplayedPrefix, Error);
            }
            Ioc.stop();
        },
        [&Failure, &Ioc](std::exception_ptr Error)
        {
            Failure = std::move(Error);
            Ioc.stop();
        });
    Ioc.run();

    EXPECT_EQ(Failure, nullptr);
    EXPECT_FALSE(Result.success);
    ASSERT_NE(Result.transport, nullptr);
    EXPECT_EQ(Replayed, ReplayedPrefix.size());
    EXPECT_EQ(ReplayedPrefix.front(), std::byte{0x16});
}

TEST(RecognitionPipeline, ClosesTransportWhenSchemeExceptionFollowsWrite)
{
    const auto Record = Preview::Testing::RecognitionWire::MakeTlsClientHello("example.com");
    Net::io_context Ioc;
    auto [a, b] = MakeMemoryPair(Ioc.get_executor());
    auto Client = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(b));
    rec::SniRouteTable Routes;
    Routes.Add("example.com", "write-throw", rec::RouteOptions{rec::ProtocolType::Tls, false});
    rec::SchemeExecutor Executor;
    ASSERT_TRUE(Executor.RegisterScheme(
        "write-throw", [](SharedTransmission Inbound) -> Net::awaitable<SharedTransmission>
        {
            std::array<std::byte, 1> Byte{std::byte{0xA5}};
            std::error_code Error;
            (void)co_await Inbound->async_write_some(Byte, Error);
            throw std::runtime_error("scheme write failure");
            co_return nullptr;
        }));
    rec::Pipeline Pipeline(&Routes, &Executor);
    rec::RecognizeResult Result;
    std::exception_ptr Failure;

    Net::co_spawn(
        Ioc,
        [Peer, Client, &Pipeline, &Result, &Ioc, Record]() -> Net::awaitable<void>
        {
            std::error_code Error;
            co_await Peer->async_write_some(Record, Error);
            Result = co_await Pipeline.Recognize(Client);
            Ioc.stop();
        },
        [&Failure, &Ioc](std::exception_ptr Error)
        {
            Failure = std::move(Error);
            Ioc.stop();
        });
    Ioc.run();

    EXPECT_EQ(Failure, nullptr);
    EXPECT_FALSE(Result.success);
    EXPECT_EQ(Result.transport, nullptr);
    EXPECT_FALSE(Client->IsOpen());
}

// ── Pipeline ──

TEST(RecognitionPipeline, DetectAndRewind)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    rec::Pipeline pipe;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 std::array<std::byte, 22> vless{};
                 vless[0] = std::byte{0x00};
                 vless[17] = std::byte{0x00};
                 vless[18] = std::byte{0x01};
                 vless[19] = std::byte{0x01};
                 vless[20] = std::byte{0xBB};
                 vless[21] = std::byte{0x02};
                 std::error_code ec;
                 co_await sb->async_write_some(vless, ec);

                 auto Result = co_await pipe.Recognize(sa);
                 EXPECT_TRUE(Result.success);
                 EXPECT_EQ(Result.detected, rec::ProtocolType::Vless);
                 EXPECT_EQ(Result.preread.size(), vless.size());

                 // 回注后可读完整 vless 头
                 std::array<std::byte, 22> buf{};
                 const auto n = co_await Result.transport->async_read_some(buf, ec);
                 EXPECT_EQ(n, vless.size());
             });
}

TEST(RecognitionPipeline, UnknownPassthrough)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    rec::Pipeline pipe;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
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

TEST(RecognitionPipeline, LegacySuccessReportsAcceptedStatus)
{
    Net::io_context Io;
    auto [A, B] = MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Preview::MemoryStream>(std::move(A));
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(B));
    rec::Pipeline Pipeline;
    rec::RecognizeResult Result;

    RunCoro(Io,
             [Client, Peer, &Pipeline, &Result]() -> Net::awaitable<void>
             {
                 const auto Wire = Preview::Testing::RecognitionWire::MakeHttp();
                 std::error_code Error;
                 co_await Peer->async_write_some(Wire, Error);
                 Result = co_await Pipeline.Recognize(Client);
             });

    EXPECT_TRUE(Result.success);
    EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
}

TEST(RecognitionPipeline, LegacyPathHonorsPreCancelledControl)
{
    Net::io_context Io;
    auto [A, B] = MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Preview::MemoryStream>(std::move(A));
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(B));

    rec::Pipeline Pipeline;
    rec::ProbeBuffer Buffer(rec::MaxTlsClientHelloBytes);
    rec::RecognitionControl Control;
    bool CancelCalled = false;
    Control.Cancelled = [] { return true; };
    Control.CancelTransport = [&CancelCalled] { CancelCalled = true; };

    RunCoro(Io,
             [Client, Peer, &Pipeline, &Buffer, &Control]() -> Net::awaitable<void>
             {
                 const std::array<std::byte, 2> Greeting{std::byte{0x05}, std::byte{0x01}};
                 std::error_code Error;
                 co_await Peer->async_write_some(Greeting, Error);
                 auto Result = co_await Pipeline.Recognize(Client, Buffer, std::move(Control));
                 EXPECT_FALSE(Result.success);
                 EXPECT_TRUE(Result.Cancelled);
                 EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
             });

    EXPECT_TRUE(CancelCalled);
}

TEST(RecognitionPipeline, LegacyPathPreservesPartialPrefixOnCancellation)
{
    Net::io_context Io;
    auto [A, B] = MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Preview::MemoryStream>(std::move(A));
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(B));

    rec::Pipeline Pipeline;
    rec::ProbeBuffer Buffer(rec::MaxTlsClientHelloBytes);
    rec::RecognitionControl Control;
    Control.Wait = [Executor = Io.get_executor()]
    {
        return WaitForRecognitionEvent(Executor, std::chrono::milliseconds(1),
                                       rec::RecognitionControlEvent::Cancelled);
    };
    Control.WaitCancellationSafe = true;
    Control.CancelTransport = [Client] { Client->Cancel(); };

    rec::RecognizeResult Result;
    std::array<std::byte, 1> Replayed{};
    std::size_t ReplayedCount = 0;
    RunCoro(Io,
             [Client, Peer, &Pipeline, &Buffer, &Control, &Result, &Replayed, &ReplayedCount]()
                 -> Net::awaitable<void>
             {
                 const std::array<std::byte, 1> Prefix{std::byte{0x05}};
                 std::error_code Error;
                 co_await Peer->async_write_some(Prefix, Error);
                 Result = co_await Pipeline.Recognize(Client, Buffer, std::move(Control));
                 if (Result.transport)
                 {
                     ReplayedCount = co_await Result.transport->async_read_some(Replayed, Error);
                 }
             });

    EXPECT_FALSE(Result.success);
    EXPECT_TRUE(Result.Cancelled);
    ASSERT_EQ(Result.preread.size(), 1U);
    EXPECT_EQ(Result.preread.front(), std::byte{0x05});
    ASSERT_NE(Result.transport, nullptr);
    EXPECT_EQ(ReplayedCount, 1U);
    EXPECT_EQ(Replayed.front(), std::byte{0x05});
}
