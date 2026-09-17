/**
 * @file Ss2022GatewayTest.cpp
 * @brief SS2022 UDP ingress authentication and outbound relay contract.
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <Preview/Ingress/Ss2022Gateway.hpp>
#include <Preview/Protocols/Shadowsocks2022/ResponseCodec.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Ss = Preview::Shadowsocks2022;

    auto MakeKey() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Key{};
        for (std::size_t Index = 0; Index < Key.size(); ++Index)
        {
            Key[Index] = static_cast<std::uint8_t>(Index + 1U);
        }
        return Key;
    }

    TEST(Ss2022Gateway, AuthenticatedPacketRelaysAndBuildsServerPacket)
    {
        Net::io_context Io;
        const auto Key = MakeKey();
        Net::ip::udp::socket Echo(Io, Net::ip::udp::endpoint(Net::ip::udp::v4(), 0));
        const auto EchoEndpoint = Echo.local_endpoint();
        std::vector<std::uint8_t> ResponseWire;
        auto ResponsePeer = std::make_shared<Net::ip::udp::endpoint>();

        Net::co_spawn(
            Io,
            [&Echo]() -> Net::awaitable<void>
            {
                std::array<std::byte, 2048> Buffer{};
                Net::ip::udp::endpoint Peer;
                boost::system::error_code Error;
                const auto Size = co_await Echo.async_receive_from(
                    Net::buffer(Buffer), Peer,
                    Net::redirect_error(Net::use_awaitable, Error));
                if (!Error)
                {
                    (void)co_await Echo.async_send_to(
                        Net::buffer(Buffer.data(), Size), Peer,
                        Net::redirect_error(Net::use_awaitable, Error));
                }
                co_return;
            },
            Net::detached);

        Preview::Ingress::Ss2022Gateway::Options Options;
        Options.Executor = Io.get_executor();
        Options.Keys = {Key};
        Options.Send = [&ResponseWire, ResponsePeer](
                           std::span<const std::byte> Data,
                           const Net::ip::udp::endpoint &Peer)
            -> Net::awaitable<boost::system::error_code>
        {
            ResponseWire.clear();
            for (const auto Byte : Data)
            {
                ResponseWire.push_back(std::to_integer<std::uint8_t>(Byte));
            }
            *ResponsePeer = Peer;
            co_return boost::system::error_code{};
        };
        auto Gateway = std::make_shared<Preview::Ingress::Ss2022Gateway>(std::move(Options));

        const Ss::Address Target{Ss::AddressType::Ipv4, "127.0.0.1", EchoEndpoint.port()};
        const std::string Payload = "ss2022-gateway-payload";
        const auto Wire = Ss::BuildUdpPacket(Ss::UdpBuildInput{
            std::span<const std::uint8_t>(Key), 0, &Target,
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Payload.data()),
                                          Payload.size())});
        ASSERT_FALSE(Wire.empty());

        Preview::Ingress::UdpPacket Packet;
        Packet.Payload.assign(reinterpret_cast<const std::byte *>(Wire.data()),
                              reinterpret_cast<const std::byte *>(Wire.data() + Wire.size()));
        Packet.Peer = Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 42000);
        Packet.Classification.Kind = Preview::Ingress::DatagramKind::Ordinary;
        ASSERT_TRUE(Gateway->Handle(std::move(Packet)));
        Io.run();

        ASSERT_FALSE(ResponseWire.empty());
        Ss::Address ResponseTarget;
        std::vector<std::uint8_t> ResponsePayload;
        std::array<std::uint8_t, Ss::SessionIdLen> ClientSession{};
        std::uint8_t HeaderType = 0;
        EXPECT_EQ(Ss::ParseUdpPacket(Ss::UdpParseInput{
                      std::span<const std::uint8_t>(Key), ResponseWire, &ResponseTarget,
                      &ResponsePayload, nullptr, nullptr, nullptr, &HeaderType, &ClientSession}),
                  Preview::Error::None);
        EXPECT_EQ(HeaderType, Ss::HeaderTypeServer);
        EXPECT_EQ(std::string(ResponsePayload.begin(), ResponsePayload.end()), Payload);
        EXPECT_EQ(ResponsePeer->port(), 42000U);
    }

    TEST(Ss2022Gateway, BadAuthenticationDoesNotReachOutbound)
    {
        Net::io_context Io;
        const auto Key = MakeKey();
        bool Sent = false;
        Preview::Ingress::Ss2022Gateway::Options Options;
        Options.Executor = Io.get_executor();
        Options.Keys = {Key};
        Options.Send = [&Sent](std::span<const std::byte>, const Net::ip::udp::endpoint &)
            -> Net::awaitable<boost::system::error_code>
        {
            Sent = true;
            co_return boost::system::error_code{};
        };
        auto Gateway = std::make_shared<Preview::Ingress::Ss2022Gateway>(std::move(Options));

        auto WrongKey = Key;
        WrongKey[0] ^= 0xFFU;
        const Ss::Address Target{Ss::AddressType::Ipv4, "127.0.0.1", 9};
        const auto Wire = Ss::BuildUdpPacket(Ss::UdpBuildInput{
            std::span<const std::uint8_t>(WrongKey), 0, &Target,
            std::span<const std::uint8_t>{}});
        ASSERT_FALSE(Wire.empty());
        Preview::Ingress::UdpPacket Packet;
        Packet.Payload.assign(reinterpret_cast<const std::byte *>(Wire.data()),
                              reinterpret_cast<const std::byte *>(Wire.data() + Wire.size()));
        Packet.Peer = Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 42001);
        Packet.Classification.Kind = Preview::Ingress::DatagramKind::Ordinary;
        ASSERT_TRUE(Gateway->Handle(std::move(Packet)));
        Io.run();

        EXPECT_FALSE(Sent);
    }

} // namespace
