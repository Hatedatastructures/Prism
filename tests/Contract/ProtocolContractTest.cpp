/**
 * @file ProtocolContractTest.cpp
 * @brief psm 与 Preview 协议线级契约对拍
 * @details 使用同一组地址、请求和错误输入，分别调用生产 psm
 *          与 Preview codec，比较 wire 字节、解析字段和失败语义。
 *          该测试是两套类型体系的唯一并列依赖点。
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include <prism/crypto/aead.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/crypto/block.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/codec/framing.hpp>
#include <prism/protocol/shadowsocks/util/datagram.hpp>
#include <prism/protocol/socks5/codec/framing.hpp>
#include <prism/protocol/vless/codec/framing.hpp>
#include <prism/protocol/vmess/codec/kdf.hpp>
#include <prism/protocol/trojan/codec/framing.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>

#include <preview/Protocols/Mux/Smux/Codec.hpp>
#include <preview/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Protocols/Vless/Codec.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>

namespace
{

    auto ToBytes(const psm::memory::vector<std::byte> &Data) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result;
        Result.reserve(Data.size());
        for (const auto Byte : Data)
        {
            Result.push_back(std::to_integer<std::uint8_t>(Byte));
        }
        return Result;
    }

    auto ToBytes(const std::span<const std::byte> Data) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result;
        Result.reserve(Data.size());
        for (const auto Byte : Data)
        {
            Result.push_back(std::to_integer<std::uint8_t>(Byte));
        }
        return Result;
    }

    [[nodiscard]] auto BuildProductionUdpRequest(
        std::span<const std::uint8_t> Psk, const std::array<std::uint8_t, 8> &SessionId,
        const std::uint64_t PacketId, std::span<const std::uint8_t> AddressWire,
        std::span<const std::uint8_t> Payload, const std::uint64_t Timestamp)
        -> std::vector<std::uint8_t>
    {
        using namespace psm::protocol::shadowsocks;

        std::array<std::uint8_t, 8> PacketIdWire{};
        for (std::size_t I = 0; I < PacketIdWire.size(); ++I)
        {
            PacketIdWire[7 - I] = static_cast<std::uint8_t>((PacketId >> (I * 8)) & 0xFF);
        }

        std::vector<std::uint8_t> Material;
        Material.insert(Material.end(), Psk.begin(), Psk.end());
        Material.insert(Material.end(), SessionId.begin(), SessionId.end());
        const auto SessionKey = psm::crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(Material), 16);

        std::vector<std::uint8_t> Plain;
        Plain.reserve(1 + 8 + AddressWire.size() + 2 + Payload.size());
        Plain.push_back(request_type);
        for (std::size_t I = 0; I < 8; ++I)
        {
            Plain.push_back(static_cast<std::uint8_t>((Timestamp >> (56 - I * 8)) & 0xFF));
        }
        Plain.insert(Plain.end(), AddressWire.begin(), AddressWire.end());
        Plain.push_back(0);
        Plain.push_back(0);
        Plain.insert(Plain.end(), Payload.begin(), Payload.end());

        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), SessionId.data() + 4, 4);
        std::memcpy(Nonce.data() + 4, PacketIdWire.data(), PacketIdWire.size());
        psm::crypto::aead_context BodyCipher(psm::crypto::aead_cipher::aes_128_gcm, SessionKey);
        const auto BodySize = psm::crypto::aead_context::seal_size(Plain.size());
        psm::memory::vector<std::uint8_t> Body(BodySize, psm::memory::current_resource());
        const auto SealError = BodyCipher.seal(psm::crypto::seal_input{
            std::span<std::uint8_t>(Body.data(), Body.size()),
            std::span<const std::uint8_t>(Plain.data(), Plain.size()),
            std::span<const std::uint8_t>(Nonce.data(), Nonce.size()), {}});
        EXPECT_EQ(SealError, psm::fault::code::success);

        std::array<std::uint8_t, 16> Separate{};
        std::memcpy(Separate.data(), SessionId.data(), SessionId.size());
        std::memcpy(Separate.data() + SessionId.size(), PacketIdWire.data(), PacketIdWire.size());
        const auto EncryptedSeparate = psm::crypto::ecb_encrypt(
            std::span<const std::uint8_t, 16>(Separate), Psk);

        std::vector<std::uint8_t> Wire;
        Wire.insert(Wire.end(), EncryptedSeparate.begin(), EncryptedSeparate.end());
        Wire.insert(Wire.end(), Body.begin(), Body.end());
        return Wire;
    }

    enum class SsUdpErrorClass
    {
        Success,
        Length,
        Auth,
        Address,
        Other,
    };

    [[nodiscard]] auto NormalizeProductionUdpError(const psm::fault::code Error)
        -> SsUdpErrorClass
    {
        if (Error == psm::fault::code::success)
        {
            return SsUdpErrorClass::Success;
        }
        if (Error == psm::fault::code::crypto_error)
        {
            return SsUdpErrorClass::Auth;
        }
        if (Error == psm::fault::code::unsupported_address)
        {
            return SsUdpErrorClass::Address;
        }
        if (Error == psm::fault::code::bad_message)
        {
            return SsUdpErrorClass::Length;
        }
        return SsUdpErrorClass::Other;
    }

    [[nodiscard]] auto NormalizePreviewUdpError(const Preview::Error Error) -> SsUdpErrorClass
    {
        switch (Error)
        {
        case Preview::Error::None: return SsUdpErrorClass::Success;
        case Preview::Error::BadLength: return SsUdpErrorClass::Length;
        case Preview::Error::BadAuth: return SsUdpErrorClass::Auth;
        case Preview::Error::BadAddress: return SsUdpErrorClass::Address;
        default: return SsUdpErrorClass::Other;
        }
    }

    TEST(ProtocolContract, Socks5UdpHeaderWireMatchesProduction)
    {
        const std::vector<std::uint8_t> Payload{0xDE, 0xAD, 0xBE, 0xEF};

        psm::protocol::socks5::wire::udp_header ProductionHeader;
        ProductionHeader.destination_address =
            psm::protocol::common::ipv4_address{{8, 8, 8, 8}};
        ProductionHeader.destination_port = 53;
        ProductionHeader.frag = 0;
        psm::memory::vector<std::uint8_t> ProductionWire(psm::memory::current_resource());
        ASSERT_EQ(psm::protocol::socks5::wire::encode_hdr(ProductionHeader, ProductionWire),
                  psm::fault::code::success);
        ProductionWire.insert(ProductionWire.end(), Payload.begin(), Payload.end());

        Preview::Socks5::Address PreviewTarget;
        PreviewTarget.Type = Preview::Socks5::AddressType::Ipv4;
        PreviewTarget.Host = "8.8.8.8";
        PreviewTarget.Port = 53;
        const auto PreviewWire = Preview::Socks5::BuildUdpDatagram(
            PreviewTarget, std::span<const std::uint8_t>(Payload));

        EXPECT_EQ(std::vector<std::uint8_t>(ProductionWire.begin(), ProductionWire.end()), PreviewWire);
    }

    TEST(ProtocolContract, VlessRequestParseMatchesProduction)
    {
        const std::vector<std::uint8_t> Wire{
            0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x00, 0x01, 0x01, 0xBB, 0x02, 0x0B,
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};

        const auto Production = psm::protocol::vless::format::parse_request(
            std::span<const std::uint8_t>(Wire));
        ASSERT_TRUE(Production.has_value());

        Preview::Vless::RequestHeader PreviewRequest;
        std::size_t Consumed = 0;
        const auto PreviewError = Preview::Vless::ParseRequest(
            std::span<const std::uint8_t>(Wire), PreviewRequest, Consumed);
        ASSERT_EQ(PreviewError, Preview::Error::None);

        EXPECT_EQ(Production->port, PreviewRequest.Target.Port);
        EXPECT_EQ(Production->uuid, PreviewRequest.Uuid);
        EXPECT_EQ(Production->cmd == psm::protocol::vless::command::tcp,
                  PreviewRequest.Cmd == Preview::Vless::Command::Tcp);
        const auto *ProductionDomain =
            std::get_if<psm::protocol::common::domain_address>(&Production->destination_address);
        ASSERT_NE(ProductionDomain, nullptr);
        EXPECT_EQ(std::string_view(ProductionDomain->value.data(), ProductionDomain->length),
                  PreviewRequest.Target.Host);
        EXPECT_EQ(Consumed, Wire.size());
    }

    TEST(ProtocolContract, TrojanUdpWireMatchesProduction)
    {
        const std::vector<std::uint8_t> Payload{0x01, 0x02, 0x03};
        psm::protocol::trojan::format::udp_routed ProductionFrame;
        ProductionFrame.destination_address =
            psm::protocol::common::ipv4_address{{1, 1, 1, 1}};
        ProductionFrame.destination_port = 443;
        psm::memory::vector<std::byte> ProductionWire(psm::memory::current_resource());
        ASSERT_EQ(psm::protocol::trojan::format::build_udp_pkt(
                      ProductionFrame,
                      std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                                 Payload.size()),
                      ProductionWire),
                  psm::fault::code::success);

        Preview::Trojan::Address PreviewTarget;
        PreviewTarget.Type = Preview::Trojan::AddressType::Ipv4;
        PreviewTarget.Host = "1.1.1.1";
        PreviewTarget.Port = 443;
        const auto PreviewWire = Preview::Trojan::BuildUdpPkt(
            PreviewTarget, std::span<const std::uint8_t>(Payload));

        EXPECT_EQ(ToBytes(ProductionWire), PreviewWire);
    }

    TEST(ProtocolContract, VmessCmdKeyMatchesProduction)
    {
        constexpr std::array<std::uint8_t, 16> Uuid{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

        const auto Production = psm::protocol::vmess::codec::cmd_key_from_uuid(
            std::span<const std::uint8_t, 16>(Uuid));
        const auto PreviewKey = Preview::Vmess::CmdKeyFromUuid(
            std::span<const std::uint8_t, 16>(Uuid));

        EXPECT_EQ(Production, PreviewKey);
    }

    TEST(ProtocolContract, ShadowsocksAddressParseMatchesProduction)
    {
        const std::vector<std::uint8_t> Wire{0x03, 0x0B,
                                             'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
                                             0x01, 0xBB};

        const auto Production = psm::protocol::shadowsocks::format::parse_addr_port(
            std::span<const std::uint8_t>(Wire));
        ASSERT_EQ(Production.first, psm::fault::code::success);

        Preview::Shadowsocks2022::Address PreviewAddress;
        std::size_t Consumed = 0;
        const auto PreviewError = Preview::Shadowsocks2022::ParseAddress(
            std::span<const std::uint8_t>(Wire), PreviewAddress, Consumed);
        ASSERT_EQ(PreviewError, Preview::Error::None);

        const auto *ProductionDomain =
            std::get_if<psm::protocol::common::domain_address>(&Production.second.addr);
        ASSERT_NE(ProductionDomain, nullptr);
        EXPECT_EQ(std::string_view(ProductionDomain->value.data(), ProductionDomain->length),
                  PreviewAddress.Host);
        EXPECT_EQ(Production.second.port, PreviewAddress.Port);
        EXPECT_EQ(Production.second.offset, Consumed);
    }

    TEST(ProtocolContract, ShadowsocksSessionKeyMatchesProduction)
    {
        constexpr std::array<std::uint8_t, 16> Psk{
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        constexpr std::array<std::uint8_t, 16> Salt{
            0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
            0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F};
        std::vector<std::uint8_t> Material;
        Material.insert(Material.end(), Psk.begin(), Psk.end());
        Material.insert(Material.end(), Salt.begin(), Salt.end());

        const auto Production = psm::crypto::derive_key(
            psm::protocol::shadowsocks::kdf_context, Material, 16);
        const auto PreviewKey = Preview::Shadowsocks2022::SessionKey(Psk, Salt, 16);

        EXPECT_EQ(Production, PreviewKey);
    }

    TEST(ProtocolContract, ShadowsocksUnknownAddressTypeHasAddressError)
    {
        const std::array<std::uint8_t, 1> Wire{0xFF};
        const auto Production = psm::protocol::shadowsocks::format::parse_addr_port(Wire);

        Preview::Shadowsocks2022::Address PreviewAddress;
        std::size_t Consumed = 0;
        const auto PreviewError = Preview::Shadowsocks2022::ParseAddress(
            Wire, PreviewAddress, Consumed);

        EXPECT_EQ(Production.first, psm::fault::code::unsupported_address);
        EXPECT_EQ(PreviewError, Preview::Error::BadAddress);
    }

    TEST(ProtocolContract, InvalidInputsFailOnBothImplementations)
    {
        const std::array<std::uint8_t, 3> ShortVless{0x00, 0x01, 0x02};
        const auto Production = psm::protocol::vless::format::parse_request(
            std::span<const std::uint8_t>(ShortVless));
        Preview::Vless::RequestHeader PreviewRequest;
        std::size_t Consumed = 0;
        const auto PreviewError = Preview::Vless::ParseRequest(
            std::span<const std::uint8_t>(ShortVless), PreviewRequest, Consumed);

        EXPECT_FALSE(Production.has_value());
        EXPECT_NE(PreviewError, Preview::Error::None);
    }

    TEST(ProtocolContract, SmuxDataAndFinWireMatchesProduction)
    {
        const std::array<std::uint8_t, 4> Payload{0x41, 0x00, 0xFE, 0x7F};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());

        const auto ProductionData = psm::multiplex::smux::make_data_frame(7, PayloadBytes);
        const auto PreviewData = Preview::Mux::Smux::Codec::BuildData(7, Payload);
        EXPECT_EQ(ToBytes(ProductionData), PreviewData);

        const auto ProductionFin = psm::multiplex::smux::make_fin(7);
        const auto PreviewFin = Preview::Mux::Smux::Codec::BuildFin(7);
        EXPECT_EQ(ToBytes(std::span<const std::byte>(ProductionFin)), PreviewFin);

        const auto ProductionParsed = psm::multiplex::smux::deserialization(
            std::span<const std::byte>(ProductionData.data(),
                                       psm::multiplex::smux::frame_hdrsize));
        Preview::Mux::Smux::FrameHeader PreviewParsed{};
        const auto PreviewError = Preview::Mux::Smux::ParseHeader(
            std::span<const std::uint8_t>(PreviewData.data(), Preview::Mux::Smux::FrameHdrsize),
            PreviewParsed);

        ASSERT_TRUE(ProductionParsed.has_value());
        ASSERT_EQ(PreviewError, Preview::Error::None);
        EXPECT_EQ(ProductionParsed->stream_id, PreviewParsed.StreamId);
        EXPECT_EQ(ProductionParsed->length, PreviewParsed.length);
        EXPECT_EQ(static_cast<std::uint8_t>(ProductionParsed->cmd),
                  static_cast<std::uint8_t>(PreviewParsed.cmd));
    }

    TEST(ProtocolContract, SmuxTruncatedHeaderFailsOnBothImplementations)
    {
        const std::array<std::uint8_t, 7> ShortHeader{0x01, 0x02, 0x00, 0x00,
                                                       0x07, 0x00, 0x00};
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(ShortHeader.data()), ShortHeader.size());
        Preview::Mux::Smux::FrameHeader PreviewHeader{};

        const auto Production = psm::multiplex::smux::deserialization(Bytes);
        const auto PreviewError = Preview::Mux::Smux::ParseHeader(ShortHeader, PreviewHeader);

        EXPECT_FALSE(Production.has_value());
        EXPECT_EQ(PreviewError, Preview::Error::NeedMore);
    }

    TEST(ProtocolContract, ShadowsocksUdpWireAndErrorsMatch)
    {
        const std::array<std::uint8_t, 16> Psk{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
        const std::array<std::uint8_t, 8> SessionId{
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28};
        const std::array<std::uint8_t, 7> Payload{
            0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7};
        const std::vector<std::uint8_t> AddressWire{0x01, 1, 2, 3, 4, 0x01, 0xBB};
        const auto Timestamp = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());

        const auto ProductionWire = BuildProductionUdpRequest(
            Psk, SessionId, 7, AddressWire, Payload, Timestamp);
        Preview::Shadowsocks2022::Address PreviewTarget;
        PreviewTarget.Type = Preview::Shadowsocks2022::AddressType::Ipv4;
        PreviewTarget.Host = "1.2.3.4";
        PreviewTarget.Port = 443;
        const auto PreviewWire = Preview::Shadowsocks2022::BuildUdpPacket(
            Preview::Shadowsocks2022::UdpBuildInput{
                Psk, 7, &PreviewTarget, Payload, SessionId, Timestamp});

        EXPECT_EQ(PreviewWire, ProductionWire);

        const auto MakeRelay = [&]()
        {
            psm::protocol::shadowsocks::config Config;
            Config.psk = "AQIDBAUGBwgJCgsMDQ4PEA==";
            Config.method = psm::protocol::shadowsocks::method_aes_128;
            Config.enable_udp = true;
            return psm::protocol::shadowsocks::make_udp_relay(
                Config, std::make_shared<psm::protocol::shadowsocks::session_tracker>());
        };
        const auto Sender = boost::asio::ip::udp::endpoint(
            boost::asio::ip::make_address("127.0.0.1"), 12345);
        const auto ToBytesSpan = [](const std::vector<std::uint8_t> &Wire)
        {
            return std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Wire.data()), Wire.size());
        };

        const auto ProductionRelay = MakeRelay();
        const auto [ProductionError, ProductionResult] =
            ProductionRelay->decrypt_inbound(ToBytesSpan(ProductionWire), Sender);
        EXPECT_EQ(NormalizeProductionUdpError(ProductionError), SsUdpErrorClass::Success);
        EXPECT_EQ(ProductionResult.destination_port, 443);
        EXPECT_EQ(ProductionResult.payload.size(), Payload.size());
        EXPECT_TRUE(std::equal(ProductionResult.payload.begin(), ProductionResult.payload.end(),
                               Payload.begin(), Payload.end()));

        Preview::Shadowsocks2022::Address ParsedTarget;
        std::vector<std::uint8_t> ParsedPayload;
        const auto PreviewError = Preview::Shadowsocks2022::ParseUdpPacket(
            {Psk, ProductionWire, &ParsedTarget, &ParsedPayload});
        EXPECT_EQ(NormalizePreviewUdpError(PreviewError), SsUdpErrorClass::Success);
        EXPECT_EQ(ParsedTarget.Host, PreviewTarget.Host);
        EXPECT_EQ(ParsedTarget.Port, PreviewTarget.Port);
        EXPECT_EQ(ParsedPayload, std::vector<std::uint8_t>(Payload.begin(), Payload.end()));

        const auto PreviewRelay = MakeRelay();
        const auto [PreviewWireError, PreviewWireResult] =
            PreviewRelay->decrypt_inbound(ToBytesSpan(PreviewWire), Sender);
        EXPECT_EQ(NormalizeProductionUdpError(PreviewWireError), SsUdpErrorClass::Success);
        EXPECT_EQ(PreviewWireResult.destination_port, PreviewTarget.Port);
        EXPECT_EQ(PreviewWireResult.payload.size(), Payload.size());

        for (const auto Length : std::array<std::size_t, 4>{0, 7, 8, 15})
        {
            const std::vector<std::uint8_t> ShortKey(Length, 0x33);
            const auto Encoded = psm::crypto::base64_encode(ShortKey);
            const auto [ProductionKeyError, ProductionKey] =
                psm::protocol::shadowsocks::format::decode_psk(Encoded);
            EXPECT_EQ(ProductionKeyError, psm::fault::code::invalid_psk);
            EXPECT_TRUE(ProductionKey.empty());
            EXPECT_TRUE(Preview::Shadowsocks2022::BuildUdpPacket(
                             {ShortKey, 7, &PreviewTarget, Payload})
                             .empty());
            EXPECT_EQ(Preview::Shadowsocks2022::ParseUdpPacket(
                          {ShortKey, ProductionWire, &ParsedTarget, &ParsedPayload}),
                      Preview::Error::BadLength);
        }

        const auto Truncated = std::vector<std::uint8_t>(
            ProductionWire.begin(), ProductionWire.begin() + 10);
        const auto [ProductionTruncatedError, unusedTruncated] =
            MakeRelay()->decrypt_inbound(ToBytesSpan(Truncated), Sender);
        (void)unusedTruncated;
        const auto PreviewTruncatedError = Preview::Shadowsocks2022::ParseUdpPacket(
            {Psk, Truncated, &ParsedTarget, &ParsedPayload});
        EXPECT_EQ(NormalizeProductionUdpError(ProductionTruncatedError), SsUdpErrorClass::Length);
        EXPECT_EQ(NormalizePreviewUdpError(PreviewTruncatedError), SsUdpErrorClass::Length);

        auto Corrupted = ProductionWire;
        Corrupted.back() ^= 0x01;
        const auto [ProductionAuthError, unusedAuth] =
            MakeRelay()->decrypt_inbound(ToBytesSpan(Corrupted), Sender);
        (void)unusedAuth;
        const auto PreviewAuthError = Preview::Shadowsocks2022::ParseUdpPacket(
            {Psk, Corrupted, &ParsedTarget, &ParsedPayload});
        EXPECT_EQ(NormalizeProductionUdpError(ProductionAuthError), SsUdpErrorClass::Auth);
        EXPECT_EQ(NormalizePreviewUdpError(PreviewAuthError), SsUdpErrorClass::Auth);

        const std::vector<std::uint8_t> UnknownAddress{0xFF, 0, 0, 0, 0, 0, 0};
        const auto UnknownAddressWire = BuildProductionUdpRequest(
            Psk, SessionId, 8, UnknownAddress, Payload, Timestamp);
        const auto [ProductionAddressError, unusedAddress] =
            MakeRelay()->decrypt_inbound(ToBytesSpan(UnknownAddressWire), Sender);
        (void)unusedAddress;
        const auto PreviewAddressError = Preview::Shadowsocks2022::ParseUdpPacket(
            {Psk, UnknownAddressWire, &ParsedTarget, &ParsedPayload});
        EXPECT_EQ(NormalizeProductionUdpError(ProductionAddressError), SsUdpErrorClass::Address);
        EXPECT_EQ(NormalizePreviewUdpError(PreviewAddressError), SsUdpErrorClass::Address);

        const auto EmptyWire = BuildProductionUdpRequest(
            Psk, SessionId, 9, AddressWire, {}, Timestamp);
        const auto [ProductionEmptyError, ProductionEmptyResult] =
            MakeRelay()->decrypt_inbound(ToBytesSpan(EmptyWire), Sender);
        const auto PreviewEmptyError = Preview::Shadowsocks2022::ParseUdpPacket(
            {Psk, EmptyWire, &ParsedTarget, &ParsedPayload});
        EXPECT_EQ(NormalizeProductionUdpError(ProductionEmptyError), SsUdpErrorClass::Success);
        EXPECT_EQ(NormalizePreviewUdpError(PreviewEmptyError), SsUdpErrorClass::Success);
        EXPECT_TRUE(ProductionEmptyResult.payload.empty());
        EXPECT_TRUE(ParsedPayload.empty());
    }

} // namespace
