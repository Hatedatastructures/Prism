/**
 * @file VlessXudpTest.cpp
 * @brief VLESS XUDP（CommandMux）帧解析与回包封帧契约测试
 * @details 对齐 sing-vmess v0.2.5 `xudp.go` / `protocol.go` 的真实 wire：
 *          帧头 [2B Length][2B SessionId][1B Status][1B Option]，
 *          Length = 4 + [Network 1B][Port-first AddrPort][globalID?]，
 *          payload 长度在 Length 覆盖区之后独立 2 字节。
 *          地址族映射（sing-vmess AddressSerializer）：
 *          IPv4=0x01 / Fqdn=0x02 / IPv6=0x03，端口先于地址族字节。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <Preview/Composition/VlessXudp.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::SharedTransmission;

    /// 组装 XUDP New 帧（首帧：network + port-first 地址 + 可选 globalID + 2B payload 长度）
    auto BuildNewFrame(std::uint16_t SessionId, std::span<const std::uint8_t> AddressBody,
                       std::span<const std::uint8_t> Payload,
                       std::span<const std::uint8_t> GlobalId = {})
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Body;
        Body.push_back(0x02U); // NetworkUDP
        Body.insert(Body.end(), AddressBody.begin(), AddressBody.end());
        Body.insert(Body.end(), GlobalId.begin(), GlobalId.end());

        std::vector<std::uint8_t> Wire;
        const auto HeaderLength = static_cast<std::uint16_t>(4U + Body.size());
        Wire.push_back(static_cast<std::uint8_t>(HeaderLength >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(HeaderLength & 0xFFU));
        Wire.push_back(static_cast<std::uint8_t>(SessionId >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(SessionId & 0xFFU));
        Wire.push_back(0x01U); // StatusNew
        Wire.push_back(0x01U); // OptionData
        Wire.insert(Wire.end(), Body.begin(), Body.end());
        Wire.push_back(static_cast<std::uint8_t>(Payload.size() >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Payload.size() & 0xFFU));
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        return Wire;
    }

    /// 组装 XUDP Keep 帧（短格式 Length=4：沿用会话目标）
    auto BuildKeepShortFrame(std::uint16_t SessionId, std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire{0x00U, 0x04U,
                                       static_cast<std::uint8_t>(SessionId >> 8U),
                                       static_cast<std::uint8_t>(SessionId & 0xFFU),
                                       0x02U, 0x01U,
                                       static_cast<std::uint8_t>(Payload.size() >> 8U),
                                       static_cast<std::uint8_t>(Payload.size() & 0xFFU)};
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        return Wire;
    }

    /// 组装 XUDP Keep 帧（长格式：network + port-first 地址）
    auto BuildKeepLongFrame(std::uint16_t SessionId, std::span<const std::uint8_t> AddressBody,
                            std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Body;
        Body.push_back(0x02U);
        Body.insert(Body.end(), AddressBody.begin(), AddressBody.end());

        std::vector<std::uint8_t> Wire;
        const auto HeaderLength = static_cast<std::uint16_t>(4U + Body.size());
        Wire.push_back(static_cast<std::uint8_t>(HeaderLength >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(HeaderLength & 0xFFU));
        Wire.push_back(static_cast<std::uint8_t>(SessionId >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(SessionId & 0xFFU));
        Wire.push_back(0x02U); // StatusKeep
        Wire.push_back(0x01U); // OptionData
        Wire.insert(Wire.end(), Body.begin(), Body.end());
        Wire.push_back(static_cast<std::uint8_t>(Payload.size() >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Payload.size() & 0xFFU));
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        return Wire;
    }

    /// IPv4 port-first 地址体：[Port 2B BE][0x01][4B IPv4]
    auto Ipv4AddressBody(std::uint16_t Port, std::uint8_t A, std::uint8_t B,
                         std::uint8_t C, std::uint8_t D) -> std::vector<std::uint8_t>
    {
        return {static_cast<std::uint8_t>(Port >> 8U),
                static_cast<std::uint8_t>(Port & 0xFFU),
                0x01U, A, B, C, D};
    }

    /// Fqdn port-first 地址体：[Port 2B BE][0x02][1B len][host]
    auto FqdnAddressBody(std::uint16_t Port, std::string_view Host)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Body{static_cast<std::uint8_t>(Port >> 8U),
                                       static_cast<std::uint8_t>(Port & 0xFFU), 0x02U,
                                       static_cast<std::uint8_t>(Host.size())};
        Body.insert(Body.end(), Host.begin(), Host.end());
        return Body;
    }

    auto MakeTransport(Net::io_context &Io, const std::vector<std::uint8_t> &Wire)
        -> std::pair<SharedTransmission, SharedTransmission>
    {
        auto [Client, Server] = Preview::MakeMemoryPair(Io.get_executor());
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(Client));
        auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(Server));
        auto WriteError = std::make_shared<std::error_code>();
        Net::co_spawn(
            Io, [ClientTransport, Wire, WriteError]() -> Net::awaitable<void>
            {
                WriteError->clear();
                (void)co_await ClientTransport->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Wire.data()),
                                               Wire.size()),
                    *WriteError);
            },
            Net::detached);
        return {ClientTransport, ServerTransport};
    }

    TEST(VlessXudp, ParsesNewFrameWithPortFirstIpv4AndGlobalId)
    {
        Net::io_context Io;
        const std::array<std::uint8_t, 8> GlobalId{1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
        const std::vector<std::uint8_t> Payload{'e', 'c', 'h', 'o'};
        const auto Address = Ipv4AddressBody(443, 127, 0, 0, 1);
        const auto Wire = BuildNewFrame(7U, Address, Payload, GlobalId);
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::optional<Preview::Composition::VlessXudp::Frame> Parsed;
        Preview::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Preview::Composition::VlessXudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(Parsed->StatusValue, Preview::Composition::VlessXudp::Status::New);
        EXPECT_EQ(Parsed->SessionId, 7U);
        EXPECT_TRUE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Host, "127.0.0.1");
        EXPECT_EQ(Parsed->Port, 443U);
        EXPECT_EQ(Parsed->Payload, Payload);
        Client->Close();
    }

    TEST(VlessXudp, ParsesFqdnAddressWithPortFirst)
    {
        Net::io_context Io;
        const std::vector<std::uint8_t> Payload{'h', 'i'};
        const auto Address = FqdnAddressBody(53, "example.com");
        const auto Wire = BuildNewFrame(1U, Address, Payload);
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::optional<Preview::Composition::VlessXudp::Frame> Parsed;
        Preview::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Preview::Composition::VlessXudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_TRUE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Host, "example.com");
        EXPECT_EQ(Parsed->Port, 53U);
        EXPECT_EQ(Parsed->Payload, Payload);
        Client->Close();
    }

    TEST(VlessXudp, ParsesKeepShortFrameReusingSessionTarget)
    {
        Net::io_context Io;
        const std::vector<std::uint8_t> Payload{'k', 'e', 'e', 'p'};
        const auto Wire = BuildKeepShortFrame(3U, Payload);
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::optional<Preview::Composition::VlessXudp::Frame> Parsed;
        Preview::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Preview::Composition::VlessXudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(Parsed->StatusValue, Preview::Composition::VlessXudp::Status::Keep);
        EXPECT_EQ(Parsed->SessionId, 3U);
        EXPECT_FALSE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Payload, Payload);
        Client->Close();
    }

    TEST(VlessXudp, ParsesKeepLongFrameWithPortFirstAddress)
    {
        Net::io_context Io;
        const std::vector<std::uint8_t> Payload{'l', 'o', 'n', 'g'};
        const auto Address = Ipv4AddressBody(8080, 10, 0, 0, 5);
        const auto Wire = BuildKeepLongFrame(9U, Address, Payload);
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::optional<Preview::Composition::VlessXudp::Frame> Parsed;
        Preview::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Preview::Composition::VlessXudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(Parsed->StatusValue, Preview::Composition::VlessXudp::Status::Keep);
        EXPECT_EQ(Parsed->SessionId, 9U);
        EXPECT_TRUE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Host, "10.0.0.5");
        EXPECT_EQ(Parsed->Port, 8080U);
        EXPECT_EQ(Parsed->Payload, Payload);
        Client->Close();
    }

    TEST(VlessXudp, WritesKeepFrameWithSessionIdAndPortFirstSourceAddress)
    {
        Net::io_context Io;
        auto [Client, Server] = Preview::MakeMemoryPair(Io.get_executor());
        auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(Server));
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(Client));
        const std::vector<std::uint8_t> Payload{'p', 'o', 'n', 'g'};
        const auto Source = Net::ip::udp::endpoint(Net::ip::make_address_v4("127.0.0.1"), 41000);

        std::vector<std::uint8_t> Wire;
        Preview::Testing::RunCoro(Io,
            [ServerTransport, ClientTransport, Payload, Source, &Wire]() -> Net::awaitable<void>
            {
                const auto Ok = co_await Preview::Composition::VlessXudp::WriteDatagram(
                    ServerTransport, 5U, Source, Payload);
                EXPECT_TRUE(Ok);
                constexpr std::size_t ExpectedSize = 2U + 2U + 1U + 1U + 1U + 7U + 2U + 4U;
                Wire.resize(ExpectedSize);
                std::size_t Done = 0;
                while (Done < ExpectedSize)
                {
                    std::error_code ErrorCode;
                    const auto N = co_await ClientTransport->async_read_some(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(Wire.data() + Done),
                                             ExpectedSize - Done),
                        ErrorCode);
                    if (ErrorCode || N == 0)
                    {
                        co_return;
                    }
                    Done += N;
                }
            });

        ASSERT_EQ(Wire.size(), 20U);
        EXPECT_EQ(Wire[0], 0x00U);
        EXPECT_EQ(Wire[1], 0x0CU);
        EXPECT_EQ(Wire[2], 0x00U);
        EXPECT_EQ(Wire[3], 0x05U);
        EXPECT_EQ(Wire[4], 0x02U);
        EXPECT_EQ(Wire[5], 0x01U);
        EXPECT_EQ(Wire[6], 0x02U);
        EXPECT_EQ(Wire[7], 0xA0U);
        EXPECT_EQ(Wire[8], 0x28U);
        EXPECT_EQ(Wire[9], 0x01U);
        EXPECT_EQ(Wire[10], 127U);
        EXPECT_EQ(Wire[11], 0U);
        EXPECT_EQ(Wire[12], 0U);
        EXPECT_EQ(Wire[13], 1U);
        EXPECT_EQ(Wire[14], 0x00U);
        EXPECT_EQ(Wire[15], 0x04U);
        EXPECT_EQ(std::vector<std::uint8_t>(Wire.begin() + 16, Wire.end()), Payload);
        ServerTransport->Close();
    }

} // namespace
