/**
 * @file QuicCidRegistryTest.cpp
 * @brief QUIC CID owner registry duplicate/peer conflict contract.
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <utility>

#include <Preview/Ingress/QuicCidRegistry.hpp>

namespace
{

auto MakeContext(boost::asio::any_io_executor Executor, const Preview::AccountId AccountId)
    -> std::shared_ptr<Preview::Ingress::QuicAdmissionContext>
{
    auto Context = std::make_shared<Preview::Ingress::QuicAdmissionContext>();
    Context->AccountId = AccountId;
    Context->Executor = std::move(Executor);
    Context->ExpectedAlpn = "h3";
    Context->ServerName = "quic.example";
    Context->Credential = std::make_shared<const Preview::Account::Credential>(
        Preview::Account::Credential::Password("hysteria-test"));
    Context->Dial = [](const Preview::Network::Target &)
        -> boost::asio::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
    { co_return std::pair{Preview::Fault::Code::NotSupported, Preview::SharedTransmission{}}; };
    Context->Hysteria2Stream = [](Preview::Hysteria2::Message,
                                  Preview::Hysteria2::SharedConn) -> boost::asio::awaitable<void>
    { co_return; };
    Context->Hysteria2Datagram = [](Preview::Hysteria2::SharedDgram) -> boost::asio::awaitable<void>
    { co_return; };
    return Context;
}

auto MakePacket(const std::array<std::byte, 4> &ConnectionId,
                const boost::asio::ip::udp::endpoint &Peer) -> Preview::Ingress::UdpPacket
{
    Preview::Ingress::UdpPacket Packet;
    Packet.Peer = Peer;
    Packet.Payload = {std::byte{0x01}};
    Packet.Classification.ConnectionIdBytes.assign(ConnectionId.begin(), ConnectionId.end());
    return Packet;
}

} // namespace

TEST(QuicCidRegistry, RejectsDuplicateCidAndPeerConflicts)
{
    using Registry = Preview::Ingress::QuicCidRegistry;
    using Udp = boost::asio::ip::udp;
    boost::asio::io_context Io;
    const auto MakeServer = [&Io]
    {
        Preview::Quic::ServerOptions Options;
        Options.Executor = Io.get_executor();
        return std::make_shared<Preview::Quic::Server>(std::move(Options));
    };
    const auto Context = MakeContext(Io.get_executor(), Preview::AccountId{1});
    auto Factory = [&MakeServer](std::span<const std::byte>, const Udp::endpoint &,
                                 Preview::Ingress::SharedQuicAdmissionContext)
        -> std::shared_ptr<Preview::Quic::Server>
    {
        return MakeServer();
    };
    Registry Owners(Registry::Options{std::move(Factory), Context});
    const auto Peer = Udp::endpoint(boost::asio::ip::address_v4::loopback(), 4433);
    const auto OtherPeer = Udp::endpoint(boost::asio::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> Cid{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};

    ASSERT_TRUE(Owners.Register(Registry::Cid(Cid.begin(), Cid.end()),
                                MakeServer(),
                                Peer, Context));
    EXPECT_FALSE(Owners.Register(Registry::Cid(Cid.begin(), Cid.end()),
                                 MakeServer(),
                                 OtherPeer, Context));
    const std::array<std::byte, 4> OtherCid{std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    EXPECT_FALSE(Owners.Register(Registry::Cid(OtherCid.begin(), OtherCid.end()),
                                 MakeServer(),
                                 Peer, Context));
    EXPECT_EQ(Owners.Size(), 1U);
    Owners.Close();
    EXPECT_EQ(Owners.Size(), 0U);
}

TEST(QuicCidRegistry, RejectsMissingContextAndHandlers)
{
    using Registry = Preview::Ingress::QuicCidRegistry;
    using Udp = boost::asio::ip::udp;
    boost::asio::io_context Io;
    const auto Peer = Udp::endpoint(boost::asio::ip::address_v4::loopback(), 4433);
    const std::array<std::byte, 4> Cid{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const auto Packet = MakePacket(Cid, Peer);
    Preview::Quic::ServerOptions ServerOptions;
    ServerOptions.Executor = Io.get_executor();
    auto Server = std::make_shared<Preview::Quic::Server>(std::move(ServerOptions));
    auto Factory = [](std::span<const std::byte>, const Udp::endpoint &,
                      Preview::Ingress::SharedQuicAdmissionContext)
        -> std::shared_ptr<Preview::Quic::Server>
    { return nullptr; };

    Registry MissingContext(Registry::Options{Factory, {}});
    EXPECT_FALSE(MissingContext.Handle(Packet));
    EXPECT_FALSE(MissingContext.Register(Registry::Cid(Cid.begin(), Cid.end()),
                                         std::move(Server), Peer));

    auto Incomplete = MakeContext(Io.get_executor(), Preview::AccountId{2});
    Incomplete->Hysteria2Datagram = {};
    Registry MissingHandler(Registry::Options{Factory, Incomplete});
    EXPECT_FALSE(MissingHandler.Handle(Packet));
    EXPECT_FALSE(MissingHandler.Register(
        Registry::Cid(Cid.begin(), Cid.end()),
        [&Io]
        {
            Preview::Quic::ServerOptions Options;
            Options.Executor = Io.get_executor();
            return std::make_shared<Preview::Quic::Server>(std::move(Options));
        }(),
        Peer, Incomplete));
}

TEST(QuicCidRegistry, KeepsDifferentAccountContextsIndependentPerCid)
{
    using Registry = Preview::Ingress::QuicCidRegistry;
    using Udp = boost::asio::ip::udp;
    boost::asio::io_context Io;
    const auto FirstContext = MakeContext(Io.get_executor(), Preview::AccountId{11});
    const auto SecondContext = MakeContext(Io.get_executor(), Preview::AccountId{22});
    const auto Peer = Udp::endpoint(boost::asio::ip::address_v4::loopback(), 4433);
    const auto OtherPeer = Udp::endpoint(boost::asio::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> FirstCid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> SecondCid{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    Registry Owners(Registry::Options{});

    ASSERT_TRUE(Owners.Register(
        Registry::Cid(FirstCid.begin(), FirstCid.end()),
        [&Io]
        {
            Preview::Quic::ServerOptions Options;
            Options.Executor = Io.get_executor();
            return std::make_shared<Preview::Quic::Server>(std::move(Options));
        }(),
        Peer, FirstContext));
    ASSERT_TRUE(Owners.Register(
        Registry::Cid(SecondCid.begin(), SecondCid.end()),
        [&Io]
        {
            Preview::Quic::ServerOptions Options;
            Options.Executor = Io.get_executor();
            return std::make_shared<Preview::Quic::Server>(std::move(Options));
        }(),
        OtherPeer, SecondContext));
    ASSERT_EQ(Owners.Size(), 2U);
    ASSERT_EQ(Owners.FindContext(FirstCid)->AccountId, Preview::AccountId{11});
    ASSERT_EQ(Owners.FindContext(SecondCid)->AccountId, Preview::AccountId{22});
}
