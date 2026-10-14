/** @file QuicFixture.hpp @brief 实际 Native 工厂测试的拥有材料与单用途网络测试服务。 */
#pragma once
#include "CatalogFixture.hpp"
#include <boost/asio/ssl/context.hpp>
#include <TestSupport/Preview/QuicFactory.hpp>
namespace ProviderTesting
{
    class StreamPort final : public Preview::Contract::StreamEgress
    {
    public:
        auto Connect(Preview::Network::Target)
            ->boost::asio::awaitable<std::expected<Preview::SharedTransmission,Preview::Fault::Failure>> override
        {co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::NotSupported});}
    };
    class RelayPort final : public Preview::Contract::StreamRelay
    {
    public:
        auto Run(Preview::Contract::StreamRelayRequest Request)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            std::expected<void, Preview::Fault::Failure> Result;
            if (Request.Inbound) Result = Request.Inbound->Close();
            if (Request.Outbound)
            { auto Closed = Request.Outbound->Close(); if (!Closed && Result) Result = Closed; }
            co_return Result;
        }
    };
    class DatagramPort final : public Preview::Contract::DatagramEgress
    {
    public:
        auto Exchange(Preview::Contract::DatagramExchangeRequest)->boost::asio::awaitable<Preview::Contract::DatagramExchangeResult> override
        {co_return Preview::Contract::DatagramExchangeResult{};}
    };
    class QuicFixture final
    {
    public:
        boost::asio::io_context Io;
        Preview::Foundation::GenerationPin Pin=Preview::Testing::ProviderPin();
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState=
            std::make_shared<Preview::Foundation::GenerationUseState>();
        std::shared_ptr<Preview::Testing::ProviderAccounts> Accounts=Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Token("quic-test-token"));
        std::shared_ptr<boost::asio::ip::udp::socket> Socket=std::make_shared<boost::asio::ip::udp::socket>(Io,
            boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),0));
        std::shared_ptr<boost::asio::ssl::context> Tls=std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls_server);
        std::shared_ptr<Preview::Contract::QuicDatagramSender> Sender=Preview::Testing::Quic::MakeSender(Socket);
        auto Input(std::string Family)->P::Preparation
        {
            Preview::Contract::ProtocolConfiguration Protocol{"quic-instance",Family,Family,{}, {}};
            Protocol.Quic.emplace();Protocol.Quic->Uuid="00112233-4455-6677-8899-aabbccddeeff";
            return {Pin,UseState,{{Protocol,false,false,{Pin,Accounts->Credentials,
                Accounts->Authenticator}}},{}};
        }
        auto Services()->P::BindingServices
        {
            auto Result=P::BindingServices{Io.get_executor(),{},{},{}};
            Result.Quic.Listener={Io.get_executor(),Socket,Tls,Sender};
            Result.Quic.Streams=std::make_shared<StreamPort>();Result.Quic.Relay=std::make_shared<RelayPort>();
            Result.Quic.Datagrams=std::make_shared<DatagramPort>();Result.Http3=std::make_shared<Preview::Http3::ServerFactory>();
            return Result;
        }
    };
}
