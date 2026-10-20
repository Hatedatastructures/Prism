/** @file StandardProviderTest.cpp @brief 实际服务、材料和 epoch 的发布前拒绝合同。 */
#include <gtest/gtest.h>
#include <utility>
#include "CatalogFixture.hpp"
#include <Prism/Net/Datagram/Egress.hpp>
#include <Prism/Net/Dns/Config.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Composition/Provider/ProtocolCredentialPreparation.hpp>
namespace
{
    namespace P=Prism::Composition::Provider;
    using E=Prism::Contract::ProviderError;
    TEST(StandardProvider, ExposesStableKeysAndCapabilities)
    {
        const auto Socks=Prism::Composition::Protocol::ProtocolCatalog::Find("socks5");
        const auto Ss=Prism::Composition::Protocol::ProtocolCatalog::Find("ss2022");
        ASSERT_TRUE(Socks);ASSERT_TRUE(Ss);
        EXPECT_TRUE(Socks->SupportsTcp);EXPECT_TRUE(Socks->SupportsUdp);
        EXPECT_TRUE(Ss->SupportsTcp);EXPECT_TRUE(Ss->SupportsUdp);
        EXPECT_TRUE(P::ProviderCatalog::Handles("socks5"));
        EXPECT_TRUE(P::ProviderCatalog::Handles("tuic"));
        using CredentialKind=Prism::Account::CredentialKind;
        const auto Password=Prism::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Prism::Contract::ProtocolType::Http,"secret-value");
        const auto Trojan=Prism::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Prism::Contract::ProtocolType::Trojan,"trojan-secret");
        const auto Uuid=Prism::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Prism::Contract::ProtocolType::Vless,"00112233-4455-6677-8899-aabbccddeeff");
        const auto Psk=Prism::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Prism::Contract::ProtocolType::Shadowsocks,"MDEyMzQ1Njc4OWFiY2RlZg==");
        ASSERT_TRUE(Password);ASSERT_TRUE(Trojan);ASSERT_TRUE(Uuid);ASSERT_TRUE(Psk);
        EXPECT_EQ(Password->Kind(),CredentialKind::Password);
        EXPECT_EQ(Trojan->Kind(),CredentialKind::Token);
        EXPECT_EQ(Uuid->Kind(),CredentialKind::Uuid);
        EXPECT_EQ(Psk->Kind(),CredentialKind::Psk);
        const auto Invalid=Prism::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Prism::Contract::ProtocolType::Tls,"must-not-fall-back");
        ASSERT_FALSE(Invalid);
        EXPECT_EQ(Invalid.error().Code,E::UnsupportedInstance);
    }
    TEST(StandardProvider, RegistersAndPreparesWithoutStringHotPathLookup)
    {
        ProviderTesting::Fixture Fixture;
        auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(),Fixture.Services());
        ASSERT_TRUE(Prepared);EXPECT_EQ(Prepared->Entries().size(),1);
        auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);
        auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
        ASSERT_NE(Bound->Find("socks-instance"),nullptr);
        EXPECT_EQ(Bound->Find("socks-instance")->Stream()->Name(),"socks5");
        Bound->Close();Fixture.Io.run();
    }
    TEST(StandardProvider, RejectsSocks5PublicationWithoutAuthenticationAndResolver)
    {
        ProviderTesting::Fixture Fixture;
        auto Input=Fixture.Input();Input.Instances[0].Authentication.Authenticator.reset();
        auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::MissingAuthentication);
        Input=Fixture.Input();Input.Instances[0].Udp=true;
        auto MissingResolver=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_FALSE(MissingResolver);EXPECT_EQ(MissingResolver.error().Code,E::MissingResolver);
    }
    TEST(StandardProvider, RejectsSs2022PublicationWithoutAccountKeysAndRawSender)
    {
        ProviderTesting::Fixture Fixture;
        Prism::Shadowsocks2022::Preparation Input{"ss-instance",Fixture.Pin,{.RawUdp=true}};
        auto Prepared=Prism::Shadowsocks2022::Prepare(Input,{Fixture.Io.get_executor(),{}, {}, {}, {}});
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::GenerationMismatch);
        auto Auth=Fixture.Input().Instances[0].Authentication;
        Prepared=Prism::Shadowsocks2022::Prepare(Input,{Fixture.Io.get_executor(),Auth,{}, {}, {}});
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::MissingResolver);
    }
    TEST(StandardProvider, RejectsEqualNumericEpochWithDifferentGenerationOwner)
    {
        ProviderTesting::Fixture Fixture;
        auto Input=Fixture.Input();Input.Generation=Prism::Testing::ProviderPin();
        auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::GenerationMismatch);
    }
    TEST(StandardProvider, BindRechecksMissingAuthenticationBeforePublication)
    {
        ProviderTesting::Fixture Fixture;
        Prism::Socks5::ServerConfig Config;Config.EnableAuth=true;Config.EnableUdp=false;
        auto Auth=Fixture.Input().Instances[0].Authentication;
        auto Prepared=Prism::Socks5::Prepare({"socks",Fixture.Pin,Config},{Fixture.Io.get_executor(),Auth,{}});
        ASSERT_TRUE(Prepared);
        Prepared->Services.Authentication.Authenticator.reset();
        auto Bound=Prism::Socks5::Bind(std::move(*Prepared),{});
        EXPECT_FALSE(Bound);
    }
    TEST(StandardProvider, InvalidAccountKeyCannotPublishTcpFactory)
    {
        ProviderTesting::Fixture Fixture;
        auto Auth=Fixture.Input().Instances[0].Authentication;
        auto Prepared=Prism::Shadowsocks2022::Prepare({"ss",Fixture.Pin,{}},
            {Fixture.Io.get_executor(),Auth,{},{},{}});
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::InvalidCredential);
        EXPECT_EQ(Prepared.error().Path,"Accounts.Credential");
    }
    TEST(StandardProvider, RawUdpRequiresRealSenderBeforePublication)
    {
        ProviderTesting::Fixture Fixture;
        auto Directory=Prism::Testing::ProviderAccount(Prism::Account::Credential::Psk(std::string(16,'p')));
        auto Resolver=std::make_shared<Prism::Network::Dns::Resolver>(Fixture.Io.get_executor(),Prism::Network::Dns::Config{});
        Prism::Shadowsocks2022::BindingServices Services{
            .Executor=Fixture.Io.get_executor(),
            .Authentication={Fixture.Pin,Directory->Credentials,Directory->Authenticator},
            .Egress=std::make_shared<Prism::Network::DatagramEgress>(Resolver),
        };
        auto Prepared=Prism::Shadowsocks2022::Prepare(
            {"ss",Fixture.Pin,{.RawUdp=true}},std::move(Services));
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::MissingSender);
        EXPECT_EQ(Prepared.error().Path,"Datagrams.Sender");
    }
}
