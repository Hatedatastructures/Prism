/** @file StandardProviderTest.cpp @brief 实际服务、材料和 epoch 的发布前拒绝合同。 */
#include <gtest/gtest.h>
#include "CatalogFixture.hpp"
#include <Preview/Net/Datagram/Egress.hpp>
#include <Preview/Composition/Provider/ProtocolCredentialPreparation.hpp>
namespace
{
    namespace P=Preview::Composition::Provider;
    using E=Preview::Contract::ProviderError;
    TEST(StandardProvider, ExposesStableKeysAndCapabilities)
    {
        const auto Socks=Preview::Composition::Protocol::ProtocolCatalog::Find("socks5");
        const auto Ss=Preview::Composition::Protocol::ProtocolCatalog::Find("ss2022");
        ASSERT_TRUE(Socks);ASSERT_TRUE(Ss);
        EXPECT_TRUE(Socks->SupportsTcp);EXPECT_TRUE(Socks->SupportsUdp);
        EXPECT_TRUE(Ss->SupportsTcp);EXPECT_TRUE(Ss->SupportsUdp);
        EXPECT_TRUE(P::ProviderCatalog::Handles("socks5"));
        EXPECT_TRUE(P::ProviderCatalog::Handles("tuic"));
        using CredentialKind=Preview::Account::CredentialKind;
        const auto Password=Preview::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Preview::Contract::ProtocolType::Http,"secret-value");
        const auto Trojan=Preview::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Preview::Contract::ProtocolType::Trojan,"trojan-secret");
        const auto Uuid=Preview::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Preview::Contract::ProtocolType::Vless,"00112233-4455-6677-8899-aabbccddeeff");
        const auto Psk=Preview::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Preview::Contract::ProtocolType::Shadowsocks,"MDEyMzQ1Njc4OWFiY2RlZg==");
        ASSERT_TRUE(Password);ASSERT_TRUE(Trojan);ASSERT_TRUE(Uuid);ASSERT_TRUE(Psk);
        EXPECT_EQ(Password->Kind(),CredentialKind::Password);
        EXPECT_EQ(Trojan->Kind(),CredentialKind::Token);
        EXPECT_EQ(Uuid->Kind(),CredentialKind::Uuid);
        EXPECT_EQ(Psk->Kind(),CredentialKind::Psk);
        const auto Invalid=Preview::Composition::Provider::ProtocolCredentialPreparation::Prepare(
            Preview::Contract::ProtocolType::Tls,"must-not-fall-back");
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
        Preview::Shadowsocks2022::Preparation Input{"ss-instance",Fixture.Pin,{.RawUdp=true}};
        auto Prepared=Preview::Shadowsocks2022::Prepare(Input,{Fixture.Io.get_executor(),{}, {}, {}, {}});
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::GenerationMismatch);
        auto Auth=Fixture.Input().Instances[0].Authentication;
        Prepared=Preview::Shadowsocks2022::Prepare(Input,{Fixture.Io.get_executor(),Auth,{}, {}, {}});
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::MissingResolver);
    }
    TEST(StandardProvider, RejectsEqualNumericEpochWithDifferentGenerationOwner)
    {
        ProviderTesting::Fixture Fixture;
        auto Input=Fixture.Input();Input.Generation=Preview::Testing::ProviderPin();
        auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::GenerationMismatch);
    }
    TEST(StandardProvider, BindRechecksMissingAuthenticationBeforePublication)
    {
        ProviderTesting::Fixture Fixture;
        Preview::Socks5::ServerConfig Config;Config.EnableAuth=true;Config.EnableUdp=false;
        auto Auth=Fixture.Input().Instances[0].Authentication;
        auto Prepared=Preview::Socks5::Prepare({"socks",Fixture.Pin,Config},{Fixture.Io.get_executor(),Auth,{}});
        ASSERT_TRUE(Prepared);
        Prepared->Services.Authentication.Authenticator.reset();
        auto Bound=Preview::Socks5::Bind(std::move(*Prepared),{});
        EXPECT_FALSE(Bound);
    }
    TEST(StandardProvider, InvalidAccountKeyCannotPublishTcpFactory)
    {
        ProviderTesting::Fixture Fixture;
        auto Auth=Fixture.Input().Instances[0].Authentication;
        auto Prepared=Preview::Shadowsocks2022::Prepare({"ss",Fixture.Pin,{}},
            {Fixture.Io.get_executor(),Auth,{},{},{}});
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::InvalidCredential);
        EXPECT_EQ(Prepared.error().Path,"Accounts.Credential");
    }
    TEST(StandardProvider, RawUdpRequiresRealSenderBeforePublication)
    {
        ProviderTesting::Fixture Fixture;
        auto Directory=Preview::Testing::ProviderAccount(Preview::Account::Credential::Psk(std::string(16,'p')));
        auto Resolver=std::make_shared<Preview::Network::Dns::Resolver>(Fixture.Io.get_executor(),Preview::Network::Dns::Config{});
        auto Prepared=Preview::Shadowsocks2022::Prepare({"ss",Fixture.Pin,{.RawUdp=true}},
            {Fixture.Io.get_executor(),{Fixture.Pin,Directory->Credentials,Directory->Authenticator},
                std::make_shared<Preview::Network::DatagramEgress>(Resolver),{},{}});
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::MissingSender);
        EXPECT_EQ(Prepared.error().Path,"Datagrams.Sender");
    }
}
