/**
 * @file TlsTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "Support.hpp"

#include <Prism/Runtime/Recognition/TlsRecordReader.hpp>
#include <boost/asio/detached.hpp>

namespace
{
    /**
     * @brief 读取预读 TLS 前缀后的完整 record 并核对字节内容。
     */
    struct TlsRecordRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Source;
        std::array<std::byte, 2> Prefix;
        std::array<std::uint8_t, 9> Record;
    };

    auto RunTlsRecordScenario(TlsRecordRequest Request) -> Net::awaitable<void>
    {
        const auto Result = co_await rec::ReadTlsRecord(*Request.Source, Request.Prefix);
        EXPECT_EQ(Result.Status, Error::None);
        EXPECT_FALSE(Result.Terminal.Failed());
        EXPECT_EQ(Result.Record.size(), Request.Record.size());
        if (Result.Record.size() != Request.Record.size())
        {
            co_return;
        }
        EXPECT_TRUE(std::equal(Result.Record.begin(), Result.Record.end(),
            Request.Record.begin(), Request.Record.end()));
    }
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
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));
    const std::array<std::uint8_t, 9> Record{
        0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};
    const std::array<std::byte, 2> Prefix{
        static_cast<std::byte>(Record[0]), static_cast<std::byte>(Record[1])};

    Net::co_spawn(
        ioc,
        [sb, Record]() -> Net::awaitable<void>
        {
            const auto WriteResult = co_await sb->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Record.data() + 2), 7));
            EXPECT_FALSE(WriteResult.Failure.Failed());
            EXPECT_EQ(WriteResult.Bytes, 7U);
        },
        Net::detached);

    RunCoro(ioc, RunTlsRecordScenario(TlsRecordRequest{sa, Prefix, Record}));
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

    auto InvalidRecordVersion = Prism::Testing::RecognitionWire::MakeTlsClientHello("invalid-version.example");
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
