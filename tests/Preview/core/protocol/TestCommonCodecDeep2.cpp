/**
 * @file TestCommonCodecDeep2.cpp
 * @brief 测试库 Codec 第二轮剩余分支深度测试
 * @details 覆盖 hysteria2（地址 ipv4/ipv6 解析截断与成功、BuildUdp
 *          空目标、Parser need_more）、anytls（认证帧长度不足）、
 *          reality（base64url 2 字节余数编码、非法字符解码、大写
 *          hex 分支）、socks5（Remaining / TakeRemaining 空返回）。
 */

#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Common/Read.hpp>
#include <Preview/Protocols/Hysteria2/Codec.hpp>
#include <Preview/Protocols/Shadowsocks2022/RequestCodec.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>
#include <Preview/Protocols/Anytls/Codec.hpp>
#include <Preview/Protocols/Reality/Codec.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Anytls = Preview::Anytls;
    namespace Fault = Preview::Fault;
    namespace Hysteria2 = Preview::Hysteria2;
    namespace Net = boost::asio;
    namespace Protocol = Preview::Protocol;
    namespace Reality = Preview::Reality;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Tuic = Preview::Tuic;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::PreviewMockTransport;

    template <typename Factory>
    auto RunCoro(Net::io_context &IoContext, Factory FactoryFn) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, FactoryFn(), [&](std::exception_ptr ErrorValue)
                      {
                          Failure = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /**
     * @brief 从初始值列表构造字节向量
     */
    auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }

    class PartialErrorTransport final : public Preview::Transmission
    {
    public:
        explicit PartialErrorTransport(Net::any_io_executor Ex, const bool WriteMode = false)
            : Ex_(std::move(Ex)), WriteMode_(WriteMode)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Ex_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            if (WriteMode_)
            {
                Error = std::make_error_code(std::errc::connection_reset);
                co_return 0;
            }
            Error = std::make_error_code(std::errc::connection_reset);
            if (Consumed_ || Buffer.size() < Data_.size())
            {
                co_return 0;
            }
            std::copy(Data_.begin(), Data_.end(), Buffer.begin());
            Consumed_ = true;
            co_return Data_.size();
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            if (WriteMode_)
            {
                Error = std::make_error_code(std::errc::connection_reset);
                co_return Data_.size();
            }
            Error = std::make_error_code(std::errc::broken_pipe);
            co_return 0;
        }

        auto Close() -> void override
        {
            Closed_ = true;
        }

        auto Cancel() -> void override {}

    private:
        Net::any_io_executor Ex_;
        std::array<std::byte, 2> Data_{std::byte{0xA1}, std::byte{0xA2}};
        bool WriteMode_{false};
        bool Consumed_{false};
        bool Closed_{false};
    };

    TEST(Hysteria2CodecDeep, ParseAddressBranches)
    {
        Hysteria2::Address addr{};
        std::size_t consumed = 0;

        // ipv4 数据不足
        EXPECT_EQ(Hysteria2::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x01, 8, 8})), addr,
                                           consumed),
                  Error::NeedMore);
        // ipv6 数据不足
        EXPECT_EQ(Hysteria2::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x03, 1})), addr,
                                           consumed),
                  Error::NeedMore);
        // ipv6 成功
        std::vector<std::uint8_t> v6{0x03};
        v6.insert(v6.end(), 16, 0x42);
        v6.push_back(0x00);
        v6.push_back(0x50);
        EXPECT_EQ(Hysteria2::ParseAddress(v6, addr, consumed), Error::None);
        EXPECT_EQ(addr.Type, Hysteria2::AddressType::Ipv6);
        EXPECT_EQ(addr.Host, std::string(16, '\x42'));
        EXPECT_EQ(addr.Port, 80u);
    }

    TEST(Hysteria2CodecDeep, BuildUdpNullDst)
    {
        Hysteria2::UdpFrameInput in{};
        in.payload = std::span<const std::uint8_t>{};
        EXPECT_TRUE(Hysteria2::BuildUdp(in).empty());
    }

    TEST(Hysteria2CodecDeep, RejectsUnknownMessageKind)
    {
        Hysteria2::Message Message{};
        std::size_t Consumed = 0;
        const std::vector<std::uint8_t> Wire{0x09, 0x01, 8, 8, 8, 8, 0x00, 0x35};

        EXPECT_EQ(Hysteria2::Parse(Wire, Message, Consumed), Error::BadMessage);
        EXPECT_EQ(Consumed, 0U);
    }

    TEST(Hysteria2CodecDeep, ParserNeedMore)
    {
        Hysteria2::Parser p;
        std::error_code ec;
        EXPECT_EQ(p.Put(boost::asio::buffer(MakeBytes({0x01, 0x01, 8})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::NeedMore));
        p.Reset();
        // 成功解析（ipv4）
        std::vector<std::uint8_t> Ok{0x01, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'};
        EXPECT_EQ(p.Put(boost::asio::buffer(Ok), ec), 9u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().dst.Host, "8.8.8.8");
    }

    TEST(AnyTlsCodecDeep, ParseAuthFrameShort)
    {
        std::array<std::uint8_t, 32> Hash{};
        std::uint16_t PadLen = 0;
        // 帧头不足
        EXPECT_EQ(Anytls::ParseAuthFrame(std::span<const std::uint8_t>(MakeBytes({0x01})), Hash, PadLen),
                  Error::BadLength);
        // 头长足够但 padding 不足
        std::vector<std::uint8_t> short_pad(34, 0);
        short_pad[32] = 0x01; // PadLen = 256
        EXPECT_EQ(Anytls::ParseAuthFrame(short_pad, Hash, PadLen), Error::BadLength);
        // 成功
        std::vector<std::uint8_t> Ok(34 + 5, 0);
        EXPECT_EQ(Anytls::ParseAuthFrame(Ok, Hash, PadLen), Error::None);
    }

    TEST(RealityCodecDeep, Base64UrlBranches)
    {
        // 1 字节余数编码（i + 1 == Size 分支）
        const std::array<std::uint8_t, 4> four{1, 2, 3, 4};
        const auto enc4 = Reality::Base64urlEncode(four);
        EXPECT_EQ(enc4.size(), 6u);
        // 2 字节余数编码
        const std::array<std::uint8_t, 2> two{'a', 'b'};
        const auto enc2 = Reality::Base64urlEncode(two);
        EXPECT_EQ(enc2.size(), 3u);
        // 3 字节整块 + 2 余数
        const std::array<std::uint8_t, 5> five{1, 2, 3, 4, 5};
        const auto enc5 = Reality::Base64urlEncode(five);
        EXPECT_EQ(enc5.size(), 7u);
        // 3 字节余数分支（i + 2 == Size）
        std::array<std::uint8_t, 8> eight{};
        eight.fill(0x55);
        EXPECT_EQ(Reality::Base64urlEncode(eight).size(), 11u);
        // 往返一致性
        const auto dec = Reality::Base64urlDecode(enc5);
        EXPECT_EQ(dec.size(), 5u);
        EXPECT_EQ(dec[0], 1u);

        // 非法字符解码 → 空
        EXPECT_TRUE(Reality::Base64urlDecode("a!b").empty());
        // 大写字母解码分支
        const auto up = Reality::Base64urlDecode("QUJD");
        EXPECT_EQ(up.size(), 3u);
        EXPECT_EQ(up[0], 'A');
        // 数字与小写分支
        const auto dn = Reality::Base64urlDecode("YWJj");
        EXPECT_EQ(dn.size(), 3u);
        EXPECT_EQ(dn[0], 'a');

        // ParseShortId：大写 hex 分支 + 非法长度 + 成功
        std::array<std::uint8_t, Reality::MaxShortIdLen> sid{};
        EXPECT_FALSE(Reality::ParseShortId("ABCD1234", sid));
        EXPECT_EQ(sid[0], 0xAB);
        EXPECT_TRUE(Reality::ParseShortId("ABC", sid));
        EXPECT_TRUE(Reality::ParseShortId("ZZ", sid));
    }

    TEST(RealityCodecDeep, EmptyShortIdDecodesToZeroFilledBytes)
    {
        std::array<std::uint8_t, Reality::MaxShortIdLen> sid{};
        sid.fill(0xA5);
        EXPECT_FALSE(Reality::ParseShortId("", sid));
        EXPECT_EQ(sid, (std::array<std::uint8_t, Reality::MaxShortIdLen>{}));
    }

    TEST(Socks5CodecDeep, RemainingEmpty)
    {
        Socks5::Parser p;
        std::error_code ec;
        // 未完成解析时 Remaining / TakeRemaining 返回空
        EXPECT_TRUE(p.Remaining().empty());
        EXPECT_TRUE(p.TakeRemaining().empty());
        // 完成后无剩余
        p.Expect(Socks5::Message::Kind::Greeting);
        EXPECT_EQ(p.Put(boost::asio::buffer(MakeBytes({0x05, 0x01, 0x00})), ec), 3u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_TRUE(p.Remaining().empty());
        EXPECT_TRUE(p.TakeRemaining().empty());
    }

    TEST(CommonAddress, RejectsEmptyIpv4Segments)
    {
        std::array<std::uint8_t, 4> bytes{};
        EXPECT_FALSE(Protocol::Common::ParseIpv4Text(".1.2.3", bytes));
        EXPECT_FALSE(Protocol::Common::ParseIpv4Text("1..2.3", bytes));
        EXPECT_FALSE(Protocol::Common::ParseIpv4Text("1.2.3.", bytes));
    }

    TEST(CommonAddress, RejectsInvalidTextWithoutWritingWire)
    {
        Socks5::Address address{Socks5::AddressType::Ipv4, "300.1.1.1", 443};
        std::vector<std::uint8_t> output{0xCC};

        Protocol::Common::EncodeAddress(address, output);
        EXPECT_EQ(output, std::vector<std::uint8_t>({0xCC}));
        EXPECT_TRUE(Socks5::EncodeAddress(address).empty());
        EXPECT_TRUE(Socks5::BuildRequest(
                        Socks5::Request{Socks5::Version, Socks5::Command::Connect, 0, address})
                        .empty());
    }

    TEST(CommonAddress, RejectsInvalidIpv6AndAcceptsBinaryIpv6)
    {
        Socks5::Address address{Socks5::AddressType::Ipv6, "not-an-ipv6", 443};
        EXPECT_TRUE(Socks5::EncodeAddress(address).empty());

        address.Host.assign(16, '\x5A');
        const auto wire = Socks5::EncodeAddress(address);
        ASSERT_EQ(wire.size(), 19u);
        EXPECT_EQ(wire[0], static_cast<std::uint8_t>(Socks5::AddressType::Ipv6));
        EXPECT_EQ(wire[1], 0x5Au);
    }

    TEST(CommonAddress, RejectsInvalidAddressAcrossProtocolBuilders)
    {
        const Trojan::Address TrojanTarget{Trojan::AddressType::Ipv4, "1..2.3", 443};
        EXPECT_TRUE(Trojan::BuildRequest("credential", Trojan::Command::Connect, TrojanTarget).empty());
        EXPECT_TRUE(Trojan::BuildUdpPkt(TrojanTarget, {}).empty());

        const Hysteria2::Address HysteriaTarget{Hysteria2::AddressType::Ipv6, "not-an-ipv6", 443};
        EXPECT_TRUE(Hysteria2::BuildTcp(HysteriaTarget, {}).empty());

        Tuic::Message TuicMessage{};
        TuicMessage.Cmd = Tuic::CmdConnect;
        TuicMessage.dst = {Tuic::AddressType::Ipv4, "300.1.1.1", 443};
        EXPECT_TRUE(Tuic::Build(TuicMessage).empty());

        const Shadowsocks2022::Address SsTarget{
            Shadowsocks2022::AddressType::Domain, "", 443};
        EXPECT_TRUE(Shadowsocks2022::BuildVarHeader(SsTarget, 0).empty());
    }

    TEST(CommonRead, RejectsOverreportedReadMin)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Raw->OverreportRead = true;
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Protocol::Common::ReadMin(*Raw, Buffer, 2);
                    EXPECT_EQ(Code, Fault::Code::IoError);
                    EXPECT_EQ(Count, 0U);
                });
    }

    TEST(CommonRead, PreservesPartialReadCountWhenReadMinReturnsError)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PartialErrorTransport>(Io.get_executor());
        std::array<std::byte, 2> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Protocol::Common::ReadMin(*Raw, Buffer, 2);
                    EXPECT_EQ(Code, Fault::Code::ConnectionReset);
                    EXPECT_EQ(Count, 2U);
                    EXPECT_EQ(Buffer, (std::array<std::byte, 2>{std::byte{0xA1}, std::byte{0xA2}}));
                });
    }

    TEST(CommonRead, RejectsOverreportedReadRemaining)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Raw->OverreportRead = true;
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Protocol::Common::ReadRemaining(
                        Protocol::Common::RemainingOpts{*Raw, Buffer, 0, 2});
                    EXPECT_EQ(Code, Fault::Code::IoError);
                    EXPECT_EQ(Count, 0U);
        });
    }

    TEST(CommonRead, PreservesPartialReadCountWhenReadRemainingReturnsError)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PartialErrorTransport>(Io.get_executor());
        std::array<std::byte, 2> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Protocol::Common::ReadRemaining(
                        Protocol::Common::RemainingOpts{*Raw, Buffer, 0, 2});
                    EXPECT_EQ(Code, Fault::Code::ConnectionReset);
                    EXPECT_EQ(Count, 2U);
                    EXPECT_EQ(Buffer, (std::array<std::byte, 2>{std::byte{0xA1}, std::byte{0xA2}}));
                });
    }

    TEST(CommonRead, TransmissionAsyncReadPreservesPartialCountWhenReturningError)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PartialErrorTransport>(Io.get_executor());
        std::array<std::byte, 2> Buffer{};
        std::error_code Error;
        std::size_t Count = 0;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await Raw->AsyncRead(Buffer, Error);
                });

        EXPECT_EQ(Count, 2U);
        EXPECT_EQ(Error, std::make_error_code(std::errc::connection_reset));
    }

    TEST(CommonRead, TransmissionAsyncWritePreservesPartialCountWhenReturningError)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PartialErrorTransport>(Io.get_executor(), true);
        const std::array<std::byte, 2> Buffer{std::byte{0xB1}, std::byte{0xB2}};
        std::error_code Error;
        std::size_t Count = 0;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await Raw->AsyncWrite(Buffer, Error);
                });

        EXPECT_EQ(Count, 2U);
        EXPECT_EQ(Error, std::make_error_code(std::errc::connection_reset));
    }

    TEST(CommonRead, RejectsInvalidReadWindowBeforeSubspan)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PreviewMockTransport>(Io.get_executor());
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Protocol::Common::ReadRemaining(
                        Protocol::Common::RemainingOpts{*Raw, Buffer, 5, 5});
                    EXPECT_EQ(Code, Fault::Code::IoError);
                    EXPECT_EQ(Count, 5U);
                    EXPECT_EQ(Raw->ReadsDone, 0U);
                });
    }

    TEST(Socks5Codec, AsyncWriteRejectsOverreportedWrite)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Raw->OverreportWrite = true;
        Socks5::Serializer Serializer;
        Socks5::Message Message;
        Message.Type = Socks5::Message::Kind::Greeting;
        Message.Methods = {0x00};
        Serializer.Reset(Message);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Code = co_await Socks5::AsyncWrite(Raw, Serializer);
                    EXPECT_EQ(Code, Error::BrokenPipe);
                    EXPECT_EQ(Raw->WritesDone, 1U);
                });
    }

    TEST(Socks5Codec, AsyncReadRejectsOverreportedRead)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Raw->OverreportRead = true;
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Greeting);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Code = co_await Socks5::AsyncRead(Raw, Parser);
                    EXPECT_EQ(Code, Error::IoError);
                    EXPECT_FALSE(Parser.IsDone());
                });
    }

} // namespace
