/**
 * @file TuicFactoryTest.cpp
 * @brief TUIC Native QUIC uni-auth/exporter callback contract.
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <Preview/Composition/Quic/TuicFactory.hpp>

#include <array>
#include <memory>
#include <utility>

TEST(TuicFactory, MapsAdmissionContextToNativeAuthCallbacks)
{
    boost::asio::io_context Io;
    auto Context = std::make_shared<Preview::Ingress::QuicAdmissionContext>();
    Context->Protocol = "tuic";
    Context->ExpectedAlpn = "h3";
    Context->ServerName = "tuic.example";
    Context->Executor = Io.get_executor();
    Context->Credential = std::make_shared<const Preview::Account::Credential>(
        Preview::Account::Credential::Token("tuic-password"));
    Context->TuicPassword = "tuic-password";
    Context->TuicUuid = {0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
                         0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    Context->Dial = [](const Preview::Network::Target &)
        -> boost::asio::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
    { co_return std::pair{Preview::Fault::Code::NotSupported, Preview::SharedTransmission{}}; };
    Context->TuicStream = [](Preview::Tuic::Message, Preview::Tuic::SharedConn)
        -> boost::asio::awaitable<void>
    { co_return; };
    Context->TuicDatagram = [](Preview::Tuic::SharedDgram) -> boost::asio::awaitable<void>
    { co_return; };

    Preview::Quic::ServerOptions Options;
    Options.Executor = Io.get_executor();
    Options.ExternalReceive = true;
    Options = Preview::Composition::Quic::ConfigureTuicServer(
        std::move(Options), Preview::Ingress::SharedQuicAdmissionContext(Context));

    EXPECT_EQ(Options.ExpectedAlpn, "h3");
    EXPECT_EQ(Options.ExpectedServerName, "tuic.example");
    EXPECT_EQ(Options.MaxStreams, 64U);
    EXPECT_EQ(Options.MaxDatagrams, 64U);
    EXPECT_TRUE(static_cast<bool>(Options.OnUnidirectional));
    EXPECT_TRUE(static_cast<bool>(Options.OnExporter));
    EXPECT_TRUE(static_cast<bool>(Options.OnStream));
    EXPECT_TRUE(static_cast<bool>(Options.OnDatagram));
}
