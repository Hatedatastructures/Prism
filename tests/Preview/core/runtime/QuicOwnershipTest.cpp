/**
 * @file QuicOwnershipTest.cpp
 * @brief External QUIC server ownership and packet injection contract.
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <cstddef>
#include <memory>

#include <Preview/Protocols/Quic/Native.hpp>

TEST(QuicOwnership, ExternalReceiveServersExposeIndependentInjectionState)
{
    using Server = Preview::Quic::Server;
    using Udp = boost::asio::ip::udp;

    boost::asio::io_context Io;
    auto Socket = std::make_shared<Udp::socket>(Io);
    std::array<std::byte, 8> Packet{};
    const auto Peer = Udp::endpoint(boost::asio::ip::address_v4::loopback(), 4433);

    Preview::Quic::ServerOptions FirstOptions;
    FirstOptions.Executor = Io.get_executor();
    FirstOptions.Socket = Socket;
    FirstOptions.ExternalReceive = true;
    FirstOptions.ExpectedAlpn = "h3";
    Preview::Quic::ServerOptions SecondOptions = FirstOptions;

    auto First = std::make_shared<Server>(std::move(FirstOptions));
    auto Second = std::make_shared<Server>(std::move(SecondOptions));

    EXPECT_FALSE(First->ReceivePacket(Packet, Peer));
    EXPECT_FALSE(Second->ReceivePacket(Packet, Peer));
    First->Close();
    Second->Close();
}

TEST(QuicOwnership, ServerCallbacksAreInstanceOwnedAndCloseOnce)
{
    using Server = Preview::Quic::Server;
    using Udp = boost::asio::ip::udp;

    boost::asio::io_context Io;
    auto Socket = std::make_shared<Udp::socket>(Io);
    int FirstClosed = 0;
    int SecondClosed = 0;
    int FirstStreams = 0;
    int SecondStreams = 0;
    int FirstDatagrams = 0;
    int SecondDatagrams = 0;

    Preview::Quic::ServerOptions FirstOptions;
    FirstOptions.Executor = Io.get_executor();
    FirstOptions.Socket = Socket;
    FirstOptions.ExternalReceive = true;
    FirstOptions.OnEstablished = [](std::string Alpn) { EXPECT_TRUE(Alpn.empty()); };
    FirstOptions.OnStream = [&FirstStreams](Preview::Quic::SharedStreamProvider) { ++FirstStreams; };
    FirstOptions.OnDatagram = [&FirstDatagrams](Preview::Quic::SharedDatagramProvider)
    { ++FirstDatagrams; };
    FirstOptions.OnClosed = [&FirstClosed] { ++FirstClosed; };

    Preview::Quic::ServerOptions SecondOptions;
    SecondOptions.Executor = Io.get_executor();
    SecondOptions.Socket = Socket;
    SecondOptions.ExternalReceive = true;
    SecondOptions.ExpectedAlpn = "h3";
    SecondOptions.OnEstablished = [](std::string Alpn) { EXPECT_TRUE(Alpn.empty()); };
    SecondOptions.OnStream = [&SecondStreams](Preview::Quic::SharedStreamProvider) { ++SecondStreams; };
    SecondOptions.OnDatagram = [&SecondDatagrams](Preview::Quic::SharedDatagramProvider)
    { ++SecondDatagrams; };
    SecondOptions.OnClosed = [&SecondClosed] { ++SecondClosed; };

    auto First = std::make_shared<Server>(std::move(FirstOptions));
    auto Second = std::make_shared<Server>(std::move(SecondOptions));
    First->Start();
    Second->Start();
    First->Close();
    Second->Close();
    Io.run();

    EXPECT_EQ(FirstClosed, 1);
    EXPECT_EQ(SecondClosed, 1);
    EXPECT_EQ(FirstStreams, 0);
    EXPECT_EQ(SecondStreams, 0);
    EXPECT_EQ(FirstDatagrams, 0);
    EXPECT_EQ(SecondDatagrams, 0);
}

TEST(QuicOwnership, ServerOptionsExposeTuicAuthenticationHooks)
{
    Preview::Quic::ServerOptions Options;
    Options.OnUnidirectional = [](Preview::Quic::SharedStreamProvider) {};
    Options.OnExporter = [](Preview::Quic::ServerOptions::KeyingMaterialExporter Exporter)
    {
        EXPECT_TRUE(static_cast<bool>(Exporter));
    };

    EXPECT_TRUE(static_cast<bool>(Options.OnUnidirectional));
    EXPECT_TRUE(static_cast<bool>(Options.OnExporter));
}
