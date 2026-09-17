/**
 * @file Hysteria2FactoryTest.cpp
 * @brief Hysteria2 Native QUIC factory contract.
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <Preview/Account/Account.hpp>
#include <Preview/Composition/Quic/Hysteria2Factory.hpp>
#include <Preview/Ingress/QuicAdmissionContext.hpp>

TEST(Hysteria2Factory, PinsAlpnAndOwnsPerServerCallbacks)
{
    Preview::Quic::ServerOptions Options;
    Options.ExternalReceive = true;
    bool Closed = false;
    Preview::Composition::Quic::Hysteria2FactoryOptions Factory;
    Factory.Config.password = "hysteria-test-password";
    Factory.OnStream = [](Preview::Hysteria2::Message,
                          Preview::Hysteria2::SharedConn)
        -> boost::asio::awaitable<void>
    { co_return; };
    Factory.OnDatagram = [](Preview::Hysteria2::SharedDgram)
        -> boost::asio::awaitable<void>
    { co_return; };
    Factory.OnClosed = [&Closed] { Closed = true; };

    const auto Configured = Preview::Composition::Quic::ConfigureHysteria2Server(
        std::move(Options), std::move(Factory));

    EXPECT_EQ(Configured.ExpectedAlpn, "h3");
    EXPECT_TRUE(static_cast<bool>(Configured.OnEstablished));
    EXPECT_TRUE(static_cast<bool>(Configured.OnStream));
    EXPECT_TRUE(static_cast<bool>(Configured.OnDatagram));
    EXPECT_TRUE(static_cast<bool>(Configured.OnClosed));
    EXPECT_FALSE(Closed);
}

TEST(Hysteria2Factory, BuildsCompleteTcpResponseHeader)
{
    constexpr auto Header = Preview::Composition::Quic::Detail::MakeTcpResponseHeader();

    ASSERT_EQ(Header.size(), 3U);
    EXPECT_EQ(Header[0], 0x00U); // status
    EXPECT_EQ(Header[1], 0x00U); // message length
    EXPECT_EQ(Header[2], 0x00U); // padding length
}

TEST(Hysteria2Factory, MapsCredentialContextIntoNativeServerOptions)
{
    boost::asio::io_context Io;
    auto Directory = std::make_shared<Preview::Account::AccountDirectory>();
    auto Record = std::make_shared<Preview::Account::AccountRecord>(
        Preview::Account::AccountRecord::CreateRequest{
            Preview::AccountId{7},
            Preview::Account::Credential::Token("config-secret"),
            Preview::Account::QuotaPolicy{},
            Preview::Account::UnlimitedRatePolicy{},
            Preview::GenerationId{1}});
    ASSERT_TRUE(Directory->Upsert(std::move(Record)));

    auto Context = std::make_shared<Preview::Ingress::QuicAdmissionContext>();
    Context->AccountId = Preview::AccountId{7};
    Context->Credential = std::make_shared<const Preview::Account::Credential>(
        Preview::Account::Credential::Token("config-secret"));
    Context->Authenticator = std::make_shared<Preview::Account::ProtocolAuthenticator>(Directory);
    Context->ExpectedAlpn = "h3";
    Context->ServerName = "quic.example";
    Context->MaxStreams = 13;
    Context->MaxDatagrams = 29;
    Context->Executor = Io.get_executor();
    Context->Dial = [](const Preview::Network::Target &)
        -> boost::asio::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
    { co_return std::pair{Preview::Fault::Code::NotSupported, Preview::SharedTransmission{}}; };
    Context->Hysteria2Stream = [](Preview::Hysteria2::Message,
                                  Preview::Hysteria2::SharedConn) -> boost::asio::awaitable<void>
    { co_return; };
    Context->Hysteria2Datagram = [](Preview::Hysteria2::SharedDgram)
        -> boost::asio::awaitable<void>
    { co_return; };

    Preview::Quic::ServerOptions Options;
    Options.ExternalReceive = true;
    const auto Configured = Preview::Composition::Quic::ConfigureHysteria2Server(
        std::move(Options), Preview::Ingress::SharedQuicAdmissionContext(Context));

    EXPECT_EQ(Configured.ExpectedAlpn, "h3");
    EXPECT_EQ(Configured.ExpectedServerName, "quic.example");
    EXPECT_EQ(Configured.MaxStreams, 13U);
    EXPECT_EQ(Configured.MaxDatagrams, 29U);
    EXPECT_TRUE(static_cast<bool>(Configured.OnEstablished));
    EXPECT_TRUE(static_cast<bool>(Configured.OnStream));
    EXPECT_TRUE(static_cast<bool>(Configured.OnDatagram));
}
