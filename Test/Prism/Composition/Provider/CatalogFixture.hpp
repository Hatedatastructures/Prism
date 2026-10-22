/** @file CatalogFixture.hpp @brief 实际 provider prepare/bind 的 owning 材料 fixture。 */
#pragma once
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <boost/asio/io_context.hpp>
namespace ProviderTesting
{
    namespace P=Prism::Composition::Provider;
    class Fixture final
    {
    public:
        boost::asio::io_context Io;
        Prism::Foundation::GenerationPin Pin=Prism::Testing::ProviderPin();
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState=
            std::make_shared<Prism::Foundation::GenerationUseState>();
        std::shared_ptr<Prism::Testing::ProviderAccounts> Accounts=Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("provider-password"));
        auto Input(std::string Id="socks-instance") -> P::Preparation
        {
            Prism::Contract::ProtocolConfiguration Protocol{Id,"socks5","socks5",{}, {}};
            return {Pin,UseState,{{Protocol,true,false,{Pin,Accounts->Credentials,
                Accounts->Authenticator}}},{}};
        }
        auto Services()->P::BindingServices{return {Io.get_executor(),{},{},{}};}
    };
}
