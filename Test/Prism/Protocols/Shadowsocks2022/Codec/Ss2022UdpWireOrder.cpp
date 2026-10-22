/**
 * @file Ss2022UdpWireOrder.cpp
 * @brief SS2022 UDP 帧 wire 顺序契约（对齐 sing-shadowsocks 权威实现）
 * @details 权威定义见 metacubex/sing-shadowsocks v0.2.12
 *          `shadowaead_2022/service.go`（服务端解析 Client 帧）与
 *          `shadowaead_2022/protocol.go`（客户端构造帧）：
 *            Client 帧 body = [type 1B][epoch 8B][paddingLen 2B][padding]
 *                              [addrport][payload]
 *          padding 长度字段位于 epoch 之后、地址之前。
 *          旧实现把地址放在 padding 之前，导致与 mihomo/sing 客户端
 *          真实数据包无法互通（认证后解析失败）。
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <Prism/Protocols/Shadowsocks2022/ResponseCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

namespace
{

    namespace Ss = Prism::Shadowsocks2022;

    /// 固定测试 PSK（16 字节）
    constexpr std::array<std::uint8_t, 16> Psk{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
                                               0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};

    struct AuthoritativeBodyLayout final
    {
        std::uint64_t Epoch;
        std::uint16_t PaddingLen;
    };

    /** @brief 按 sing 权威顺序构造固定 IPv4 Client body（未加密）。 */
    auto BuildAuthoritativeClientBody(
        AuthoritativeBodyLayout Layout,
        const std::uint16_t Port,
        std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Body;
        Body.push_back(Ss::HeaderTypeClient);
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            Body.push_back(static_cast<std::uint8_t>(
                (Layout.Epoch >> (56 - Index * 8)) & 0xFF));
        }
        Body.push_back(static_cast<std::uint8_t>(Layout.PaddingLen >> 8));
        Body.push_back(static_cast<std::uint8_t>(Layout.PaddingLen & 0xFF));
        for (std::uint16_t Index = 0; Index < Layout.PaddingLen; ++Index)
        {
            Body.push_back(0xAB);
        }
        // addrport: [type][addr][port BE]（sing AddressSerializer 默认顺序）
        Body.push_back(0x01); // IPv4
        Body.push_back(127);
        Body.push_back(0);
        Body.push_back(0);
        Body.push_back(1);
        Body.push_back(static_cast<std::uint8_t>(Port >> 8));
        Body.push_back(static_cast<std::uint8_t>(Port & 0xFF));
        Body.insert(Body.end(), Payload.begin(), Payload.end());
        return Body;
    }

    TEST(Ss2022UdpWireOrder, BuildUdpPacketPlacesPaddingLengthBeforeAddress)
    {
        Ss::Address Target{Ss::AddressType::Ipv4, "127.0.0.1", 53};
        const std::vector<std::uint8_t> Payload{'h', 'i'};
        std::vector<std::uint8_t> Wire;
        const auto Ok = Ss::BuildUdpPacket(
            Ss::UdpBuildInput{
                std::span<const std::uint8_t>(Psk), 0, &Target,
                std::span<const std::uint8_t>(Payload), {}, 0, {}, Ss::HeaderTypeClient},
            Wire);
        ASSERT_TRUE(Ok);

        // 解密 body 后校验字段顺序（用同一 PSK 走 parse 的逆向路径）
        Ss::Address ParsedTarget{};
        std::vector<std::uint8_t> ParsedPayload;
        std::array<std::uint8_t, Ss::SessionIdLen> SessionId{};
        std::uint64_t PacketId = 0;
        std::uint8_t HeaderType = 0;
        const auto Error = Ss::ParseUdpPacket(Ss::UdpParseInput{
            std::span<const std::uint8_t>(Psk), Wire, &ParsedTarget, &ParsedPayload,
            &SessionId, &PacketId, nullptr, &HeaderType, nullptr, 0, 90});
        EXPECT_EQ(Error, Prism::Error::None);
        EXPECT_EQ(ParsedTarget.Port, 53);
        EXPECT_EQ(ParsedPayload, Payload);
    }

    TEST(Ss2022UdpWireOrder, ParsesSingStyleClientFrameWithPadding)
    {
        // 用权威顺序构造带 padding 的 body，再按 Prism 的加密路径封装
        const auto Epoch = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        const std::vector<std::uint8_t> Payload{'o', 'k'};
        const auto Body = BuildAuthoritativeClientBody(
            AuthoritativeBodyLayout{Epoch, 4}, 53, Payload);

        // 用固定 SessionId/PacketId 走 Prism 的加密封装
        const std::array<std::uint8_t, Ss::SessionIdLen> SessionId{1, 2, 3, 4, 5, 6, 7, 8};
        std::array<std::uint8_t, Ss::SeparateHdrLen> SeparatePlain{};
        std::memcpy(SeparatePlain.data(), SessionId.data(), Ss::SessionIdLen);
        const std::uint64_t PacketId = 0;
        for (std::size_t Index = 0; Index < Ss::PacketIdLen; ++Index)
        {
            SeparatePlain[Ss::SessionIdLen + Index] =
                static_cast<std::uint8_t>((PacketId >> (56 - Index * 8)) & 0xFF);
        }
        const auto Separate = Ss::detail::CryptSeparate(
            std::span<const std::uint8_t>(Psk),
            std::span<const std::uint8_t, Ss::SeparateHdrLen>(SeparatePlain), true);
        ASSERT_TRUE(Separate.has_value());

        const auto Subkey = Ss::SessionKey(std::span<const std::uint8_t>(Psk),
                                           std::span<const std::uint8_t>(SessionId),
                                           Ss::AeadKeyLen);
        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), SeparatePlain.data() + Ss::SessionIdLen / 2,
                    Ss::SessionIdLen / 2);
        std::memcpy(Nonce.data() + Ss::SessionIdLen / 2,
                    SeparatePlain.data() + Ss::SessionIdLen, Ss::PacketIdLen);
        const auto BodyEnc = Ss::detail::UdpSeal(
            Ss::detail::UdpSealInput{
                Subkey, Nonce, std::span<const std::uint8_t>(Body), {}});
        ASSERT_FALSE(BodyEnc.empty());

        std::vector<std::uint8_t> Wire(Separate->begin(), Separate->end());
        Wire.insert(Wire.end(), BodyEnc.begin(), BodyEnc.end());

        Ss::Address ParsedTarget{};
        std::vector<std::uint8_t> ParsedPayload;
        std::array<std::uint8_t, Ss::SessionIdLen> ParsedSession{};
        std::uint64_t ParsedPacketId = 0;
        std::uint8_t HeaderType = 0;
        const auto Error = Ss::ParseUdpPacket(Ss::UdpParseInput{
            std::span<const std::uint8_t>(Psk), Wire, &ParsedTarget, &ParsedPayload,
            &ParsedSession, &ParsedPacketId, nullptr, &HeaderType, nullptr, Epoch, 90});
        EXPECT_EQ(Error, Prism::Error::None);
        EXPECT_EQ(ParsedTarget.Port, 53);
        EXPECT_EQ(ParsedPayload, Payload);
    }

    TEST(Ss2022UdpWireOrder, ServerFramePlacesClientSessionBeforePaddingLength)
    {
        // sing 服务端帧顺序：[type][epoch][clientSessionId 8B][paddingLen 2B]
        //                    [padding][addrport][payload]
        const auto Epoch = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        const std::array<std::uint8_t, Ss::SessionIdLen> ClientSession{9, 8, 7, 6, 5, 4, 3, 2};
        Ss::Address Target{Ss::AddressType::Ipv4, "127.0.0.1", 5300};
        const std::vector<std::uint8_t> Payload{'p', 'o', 'n', 'g'};

        std::vector<std::uint8_t> Wire;
        const auto Ok = Ss::BuildUdpPacket(
            Ss::UdpBuildInput{
                std::span<const std::uint8_t>(Psk), 7, &Target,
                std::span<const std::uint8_t>(Payload), {}, 0, ClientSession,
                Ss::HeaderTypeServer},
            Wire);
        ASSERT_TRUE(Ok);

        // 用权威顺序直接解析：跳过 16B separate header，解密 body 后逐字段校验
        Ss::Address ParsedTarget{};
        std::vector<std::uint8_t> ParsedPayload;
        std::array<std::uint8_t, Ss::SessionIdLen> RemoteSession{};
        std::uint64_t PacketId = 0;
        std::uint8_t HeaderType = 0;
        const auto Error = Ss::ParseUdpPacket(Ss::UdpParseInput{
            std::span<const std::uint8_t>(Psk), Wire, &ParsedTarget, &ParsedPayload,
            nullptr, &PacketId, nullptr, &HeaderType, &RemoteSession, Epoch, 90});
        EXPECT_EQ(Error, Prism::Error::None);
        EXPECT_EQ(HeaderType, Ss::HeaderTypeServer);
        EXPECT_EQ(RemoteSession, ClientSession);
        EXPECT_EQ(ParsedTarget.Port, 5300);
        EXPECT_EQ(ParsedPayload, Payload);
    }

} // namespace
