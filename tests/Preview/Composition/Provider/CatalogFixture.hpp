/** @file CatalogFixture.hpp @brief 实际 provider prepare/bind 的 owning 材料 fixture。 */
#pragma once
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <boost/asio/io_context.hpp>
namespace ProviderTesting
{
    namespace P=Preview::Composition::Provider;
    class Fixture final
    {
    public:
        boost::asio::io_context Io;
        Preview::Foundation::GenerationPin Pin=Preview::Testing::ProviderPin();
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState=
            std::make_shared<Preview::Foundation::GenerationUseState>();
        std::shared_ptr<Preview::Testing::ProviderAccounts> Accounts=Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Password("provider-password"));
        auto Input(std::string Id="socks-instance") -> P::Preparation
        {
            Preview::Contract::ProtocolConfiguration Protocol{Id,"socks5","socks5",{}, {}};
            return {Pin,UseState,{{Protocol,true,false,{Pin,Accounts->Credentials,
                Accounts->Authenticator}}},{}};
        }
        auto Services()->P::BindingServices{return {Io.get_executor(),{},{},{}};}
    };
}
