/** @file QuicProviderTest.cpp @brief 真实 QUIC provider 的发布前能力拒绝与实例歧义合同。 */
#include "CatalogFixture.hpp"
#include "QuicFixture.hpp"
#include <Prism/Net/Services/StreamEgress.hpp>
#include <Prism/Net/Services/WorkerDialService.hpp>
#include <boost/asio/co_spawn.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace P=Prism::Composition::Provider;
    auto Input(ProviderTesting::Fixture& Fixture,std::string Family)->P::Preparation
    {
        auto Value=Fixture.Input("quic-instance");
        auto& Instance=Value.Instances.front();
        Instance.Protocol.Name=Family;Instance.Protocol.Builtin=Family;
        Instance.Protocol.Quic.emplace();Instance.Tcp=false;
        return Value;
    }
    TEST(QuicProvider, Hysteria2ReportsMissingTlsBeforePublication)
    {
        ProviderTesting::QuicFixture Fixture;
        auto Services=Fixture.Services();
        Services.Quic.Listener.Tls.reset();
        auto Prepared=P::ProviderCatalog::Prepare(
            Fixture.Input("hysteria2"),std::move(Services));
        ASSERT_FALSE(Prepared);
        EXPECT_EQ(Prepared.error().Instance,"quic-instance");
        EXPECT_EQ(Prepared.error().Path,"Quic.Tls");
    }
    TEST(QuicProvider, TuicReportsMissingTlsBeforePublication)
    {
        ProviderTesting::QuicFixture Fixture;
        auto Services=Fixture.Services();
        Services.Quic.Listener.Tls.reset();
        auto Prepared=P::ProviderCatalog::Prepare(
            Fixture.Input("tuic"),std::move(Services));
        ASSERT_FALSE(Prepared);
        EXPECT_EQ(Prepared.error().Instance,"quic-instance");
        EXPECT_EQ(Prepared.error().Path,"Quic.Tls");
    }
    TEST(QuicProvider, Hysteria2RequiresActualHttp3Service)
    {
        ProviderTesting::QuicFixture Fixture;auto Services=Fixture.Services();Services.Http3.reset();
        auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input("hysteria2"),std::move(Services));
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Path,"Quic.Http3");
    }
    TEST(QuicProvider, TuicUsesTlsExporterWithoutHttp3Dependency)
    {
        ProviderTesting::QuicFixture Fixture;auto Services=Fixture.Services();Services.Http3.reset();
        auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input("tuic"),std::move(Services));
        ASSERT_TRUE(Prepared)<<Prepared.error().Path;
    }
    TEST(QuicProvider, BoundCatalogCarriesGenerationUseStateAndUniqueIngress)
    {
        ProviderTesting::QuicFixture Fixture;
        auto InputValue=Fixture.Input("hysteria2");
        const auto UseState=InputValue.UseState;
        auto Prepared=P::ProviderCatalog::Prepare(std::move(InputValue),Fixture.Services());
        ASSERT_TRUE(Prepared);
        auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);
        auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
        EXPECT_EQ(Bound->UseState(),UseState);
        const auto Listener=Bound->QuicIngressBinding();
        ASSERT_TRUE(Listener);
        ASSERT_TRUE(*Listener);
        EXPECT_EQ((*Listener)->Id,"quic-instance");
        EXPECT_TRUE((*Listener)->Factory);
        Bound->Close();
        Fixture.Io.run();
    }
    void CheckMissingBoundarySender(std::string Family)
    {
        ProviderTesting::QuicFixture Fixture;
        auto Services=Fixture.Services();
        Services.Quic.Listener.Sender.reset();
        const auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(Family),std::move(Services));
        ASSERT_FALSE(Prepared);
        EXPECT_EQ(Prepared.error().Instance,"quic-instance");
        EXPECT_EQ(Prepared.error().Path,"Quic.Sender");
        EXPECT_EQ(Prepared.error().Code,Prism::Contract::ProviderError::MissingSender);
    }
    TEST(QuicProvider, Hysteria2RequiresBoundarySenderBeforePublication)
    {CheckMissingBoundarySender("hysteria2");}
    TEST(QuicProvider, TuicRequiresBoundarySenderBeforePublication)
    {CheckMissingBoundarySender("tuic");}
    TEST(QuicProvider, TuicRejectsTlsWithoutVersion13Exporter)
    {
        ProviderTesting::QuicFixture Fixture;ASSERT_EQ(SSL_CTX_set_max_proto_version(Fixture.Tls->native_handle(),TLS1_2_VERSION),1);
        auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input("tuic"),Fixture.Services());
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Path,"Quic.Tls.Exporter");
    }
    TEST(QuicProvider, RejectsUndistinguishableQuicInstancesOnSharedListener)
    {
        ProviderTesting::QuicFixture Fixture;auto Value=Fixture.Input("hysteria2");auto Second=Value.Instances.front();
        Second.Protocol.Id="second";Second.Protocol.Name="tuic";Second.Protocol.Builtin="tuic";
        Value.Instances.push_back(std::move(Second));auto Prepared=P::ProviderCatalog::Prepare(std::move(Value),Fixture.Services());
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Path,"Quic.Listener");
        EXPECT_EQ(Prepared.error().Code,Prism::Contract::ProviderError::AmbiguousListener);
    }
    struct NativeLifetimeDrainScenario final
    {
        P::BoundCatalog& Catalog;
        std::shared_ptr<Prism::Contract::QuicConnectionFactory> Factory;
        std::unique_ptr<Prism::Contract::QuicConnectionLease>& External;
        std::shared_ptr<Prism::Contract::QuicConnectionOwner> Native;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::shared_ptr<boost::asio::ip::udp::socket> Socket;
        std::size_t& Closed;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> Generation;

        auto Run() -> boost::asio::awaitable<void>
        {
            Native->Start();
            EXPECT_TRUE(External->RequestClose());
            EXPECT_TRUE(External->RequestClose());
            EXPECT_TRUE(co_await Catalog.Drain());
            EXPECT_TRUE(Factory->IsRetired());
            EXPECT_TRUE(Catalog.PhysicalRetirement().Complete());
            EXPECT_EQ(UseState->Outstanding(), 0U);
            EXPECT_TRUE(co_await External->Drain());
            EXPECT_TRUE(Native->State().Closed);
            EXPECT_TRUE(Socket->is_open());
            EXPECT_EQ(Closed, 1U);
            EXPECT_FALSE(Generation.expired());
        }
    };
    void CheckNativeLifetime(std::string Family)
    {
        ProviderTesting::QuicFixture Fixture;std::weak_ptr<const Prism::Foundation::GenerationLifetime> Weak=Fixture.Pin;
        auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(Family),Fixture.Services());ASSERT_TRUE(Prepared);
        auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
        auto Factory=Bound->Find("quic-instance")->Quic();ASSERT_TRUE(Factory);
        std::size_t Closed=0;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        auto Request=Prism::Testing::Quic::MakeRequest({Factory,Fixture.Pin->Id(),"quic-instance",
            {std::byte{1},std::byte{2}},{boost::asio::ip::address_v4::loopback(),4444},[&Closed]{++Closed;},&UseState});
        ASSERT_TRUE(UseState);
        EXPECT_EQ(UseState->Outstanding(), 1U);
        auto Accepted=Factory->Create(std::move(Request));
        ASSERT_TRUE(Accepted);auto Native=Accepted->SharedOwner();ASSERT_TRUE(Native);
        auto External=std::make_unique<Prism::Contract::QuicConnectionLease>(std::move(*Accepted));
        Fixture.Pin.reset();EXPECT_FALSE(Weak.expired());
        NativeLifetimeDrainScenario Scenario{
            *Bound, Factory, External, Native, UseState, Fixture.Socket, Closed, Weak};
        boost::asio::co_spawn(Fixture.Io,Scenario.Run(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});
        Fixture.Io.run();
        Scenario.Native.reset();
        External.reset();EXPECT_FALSE(Weak.expired());Native.reset();EXPECT_TRUE(Weak.expired());
    }
    TEST(QuicProvider, Hysteria2FactoryConsumesNativeAndReleasesOriginalGeneration)
    {CheckNativeLifetime("hysteria2");}
    TEST(QuicProvider, TuicFactoryConsumesNativeAndReleasesOriginalGeneration)
    {CheckNativeLifetime("tuic");}
    void CheckExternalNativeLifetime(std::string Family)
    {
        auto Context=Prism::Executor::ContextOwner::Create();
        std::weak_ptr<Prism::Executor::ContextOwner> WeakContext=Context;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakGeneration;
        std::weak_ptr<boost::asio::ssl::context> WeakTls;
        std::shared_ptr<Prism::Contract::QuicConnectionOwner> Native;
        std::size_t Closed=0;
        {
            ProviderTesting::QuicFixture Fixture;
            WeakGeneration=Fixture.Pin;WeakTls=Fixture.Tls;
            auto Services=Fixture.Services();Services.Quic.Listener.Executor=Context->Io.get_executor();
            Services.Quic.Listener.Socket=std::make_shared<boost::asio::ip::udp::socket>(Context->Io,
                boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),0));
            Services.Quic.Listener.Sender=Prism::Testing::Quic::MakeSender(Services.Quic.Listener.Socket);
            auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(Family),std::move(Services));ASSERT_TRUE(Prepared);
            auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
            auto Factory=Bound->Find("quic-instance")->Quic();
            auto Request=Prism::Testing::Quic::MakeRequest({Factory,Fixture.Pin->Id(),"quic-instance",
                {std::byte{1}},{boost::asio::ip::address_v4::loopback(),4444},[&Closed]{++Closed;}});
            auto Lease=Factory->Create(std::move(Request));ASSERT_TRUE(Lease);
            Native=Lease->SharedOwner();ASSERT_TRUE(Native);
            auto Run=[&]()->boost::asio::awaitable<void>
            {Native->Start();EXPECT_TRUE(co_await Bound->Drain());EXPECT_TRUE(co_await Lease->Drain());};
            boost::asio::co_spawn(Context->Io,Run(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});
            Context->Io.run();EXPECT_TRUE(Native->State().Closed);EXPECT_EQ(Closed,1U);
        }
        EXPECT_FALSE(WeakGeneration.expired());EXPECT_FALSE(WeakTls.expired());
        ASSERT_GT(Context.use_count(),1);
        auto FromSelf=Native;Native.reset();Native=std::move(FromSelf);
        Native->RequestClose();Context->Io.restart();EXPECT_EQ(Context->Io.run(),0U);
        Context.reset();EXPECT_FALSE(WeakContext.expired());
        Native->RequestClose();Native.reset();EXPECT_TRUE(WeakContext.expired());
        EXPECT_TRUE(WeakGeneration.expired());EXPECT_TRUE(WeakTls.expired());
    }
    TEST(QuicProvider, Hysteria2BareNativeRetainsOriginalResourcesAfterBindingDrain)
    {CheckExternalNativeLifetime("hysteria2");}
    TEST(QuicProvider, TuicBareNativeRetainsOriginalResourcesAfterBindingDrain)
    {CheckExternalNativeLifetime("tuic");}
    TEST(QuicProvider, BareDatagramRetainsChannelExecutorAfterNativeRelease)
    {
        auto Context=Prism::Executor::ContextOwner::Create();
        std::weak_ptr<Prism::Executor::ContextOwner> WeakContext=Context;
        Prism::Quic::SharedDatagramProvider Datagram;
        {
            ProviderTesting::QuicFixture Fixture;
            auto Socket=std::make_shared<boost::asio::ip::udp::socket>(Context->Io,
                boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),0));
            Prism::Quic::ServerOptions Options;
            Options.Executor=Context->Io.get_executor();Options.Socket=Socket;Options.TlsContext=Fixture.Tls;
            Options.Sender=Prism::Testing::Quic::MakeSender(Socket);
            auto Native=std::make_shared<Prism::Quic::Server>(std::move(Options));
            Datagram=Native->Datagram();ASSERT_TRUE(Datagram);
            auto Run=[&]()->boost::asio::awaitable<void>
            {
                Native->Start();
                EXPECT_TRUE(co_await Native->Drain());
            };
            boost::asio::co_spawn(Context->Io,Run(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});
            Context->Io.run();
        }
        EXPECT_TRUE(Datagram->IsClosed());ASSERT_GT(Context.use_count(),1);
        Datagram->Close();Datagram->Cancel();Context->Io.restart();EXPECT_EQ(Context->Io.run(),0U);
        Context.reset();EXPECT_FALSE(WeakContext.expired());
        Datagram->Close();Datagram->Cancel();Datagram.reset();EXPECT_TRUE(WeakContext.expired());
    }
    void CheckExternalLeaseLifetime(std::string Family)
    {
        auto Context=Prism::Executor::ContextOwner::Create();
        std::weak_ptr<Prism::Executor::ContextOwner> WeakContext=Context;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakGeneration;
        std::unique_ptr<Prism::Contract::QuicConnectionLease> External;
        {
            ProviderTesting::QuicFixture Fixture;WeakGeneration=Fixture.Pin;auto Services=Fixture.Services();
            Services.Quic.Listener.Executor=Context->Io.get_executor();
            Services.Quic.Listener.Socket=std::make_shared<boost::asio::ip::udp::socket>(Context->Io,
                boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),0));
            Services.Quic.Listener.Sender=Prism::Testing::Quic::MakeSender(Services.Quic.Listener.Socket);
            auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(Family),std::move(Services));ASSERT_TRUE(Prepared);
            auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
            auto Factory=Bound->Find("quic-instance")->Quic();
            auto Request=Prism::Testing::Quic::MakeRequest({Factory,Fixture.Pin->Id(),"quic-instance",
                {std::byte{1}},{boost::asio::ip::address_v4::loopback(),4444},{}});
            auto Lease=Factory->Create(std::move(Request));ASSERT_TRUE(Lease);
            External=std::make_unique<Prism::Contract::QuicConnectionLease>(std::move(*Lease));
            auto Run=[&]()->boost::asio::awaitable<void>
            {External->Start();EXPECT_TRUE(co_await Bound->Drain());EXPECT_TRUE(co_await External->Drain());};
            boost::asio::co_spawn(Context->Io,Run(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});Context->Io.run();
        }
        EXPECT_FALSE(WeakGeneration.expired());ASSERT_GT(Context.use_count(),1);
        Context->Io.restart();
        auto Repeat=[&]()->boost::asio::awaitable<void>{EXPECT_TRUE(co_await External->Drain());EXPECT_TRUE(co_await External->Drain());};
        boost::asio::co_spawn(Context->Io,Repeat(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});Context->Io.run();
        Context.reset();EXPECT_FALSE(WeakContext.expired());
        External->RequestClose();External.reset();EXPECT_TRUE(WeakContext.expired());EXPECT_TRUE(WeakGeneration.expired());
    }
    TEST(QuicProvider, Hysteria2BareLeaseRetainsDrainExecutorAfterNativeRelease)
    {CheckExternalLeaseLifetime("hysteria2");}
    TEST(QuicProvider, TuicBareLeaseRetainsDrainExecutorAfterNativeRelease)
    {CheckExternalLeaseLifetime("tuic");}
    void CheckQuicDnsMaterials(std::string Family)
    {
        auto Context=Prism::Executor::ContextOwner::Create();
        std::weak_ptr<Prism::Executor::ContextOwner> WeakContext=Context;
        std::weak_ptr<Prism::Network::Dns::Resolver> WeakDns;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakGeneration;
        std::weak_ptr<boost::asio::ssl::context> WeakTls;
        std::shared_ptr<Prism::Contract::QuicConnectionOwner> Native;
        bool PortReleasedOnExecutor=false;
        {
            ProviderTesting::QuicFixture Fixture;WeakGeneration=Fixture.Pin;WeakTls=Fixture.Tls;
            auto Services=Fixture.Services();const auto Executor=Context->Io.get_executor();
            auto ListenerSocket=std::make_shared<boost::asio::ip::udp::socket>(Context->Io,
                boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),0));
            Services.Quic.Listener={Executor,ListenerSocket,Fixture.Tls,
                Prism::Testing::Quic::MakeSender(ListenerSocket)};
            auto Dialer=std::make_shared<Prism::Network::Services::WorkerDialService>(
                Prism::Network::Services::WorkerDialOptions{Executor,{},std::chrono::seconds(1),true});
            auto Resolver=Dialer->Resolver();WeakDns=Resolver;
            Services.Quic.Streams=std::shared_ptr<Prism::Network::StreamEgress>(
                new Prism::Network::StreamEgress({Executor,Resolver,std::chrono::seconds(1)}),
                [&PortReleasedOnExecutor,WeakContext](Prism::Network::StreamEgress* Port)
                {auto Owner=WeakContext.lock();PortReleasedOnExecutor=Owner && Owner->Io.get_executor().running_in_this_thread();delete Port;});
            Dialer.reset();Resolver.reset();
            auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(Family),std::move(Services));ASSERT_TRUE(Prepared);
            auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
            auto Factory=Bound->Find("quic-instance")->Quic();
            auto Request=Prism::Testing::Quic::MakeRequest({Factory,Fixture.Pin->Id(),"quic-instance",
                {std::byte{1}},{boost::asio::ip::address_v4::loopback(),4444},{}});
            auto Lease=Factory->Create(std::move(Request));ASSERT_TRUE(Lease);
            Native=Lease->SharedOwner();Fixture.Pin.reset();Fixture.Tls.reset();
            auto Run=[&]()->boost::asio::awaitable<void>
            {
                Native->Start();EXPECT_FALSE(WeakDns.expired());
                EXPECT_TRUE(co_await Bound->Drain());EXPECT_TRUE(co_await Lease->Drain());
                EXPECT_TRUE(WeakDns.expired());EXPECT_TRUE(PortReleasedOnExecutor);
                EXPECT_FALSE(WeakGeneration.expired());EXPECT_FALSE(WeakTls.expired());
            };
            boost::asio::co_spawn(Context->Io,Run(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});Context->Io.run();
        }
        EXPECT_TRUE(WeakDns.expired());EXPECT_FALSE(WeakGeneration.expired());EXPECT_FALSE(WeakTls.expired());
        Context.reset();EXPECT_FALSE(WeakContext.expired());Native.reset();
        EXPECT_TRUE(WeakGeneration.expired());EXPECT_TRUE(WeakTls.expired());EXPECT_TRUE(WeakContext.expired());
    }
    TEST(QuicProvider, Hysteria2DrainReleasesActualDnsPortBeforeFinalNativeMaterial)
    {CheckQuicDnsMaterials("hysteria2");}
    TEST(QuicProvider, TuicDrainReleasesActualDnsPortBeforeFinalNativeMaterial)
    {CheckQuicDnsMaterials("tuic");}
    TEST(QuicProvider, PartialBindFailureClosesPreviouslyBoundInstanceAndConsumesCatalog)
    {
        auto Storage=std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context=Prism::Executor::ContextOwner::Create(Storage);
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakGeneration;
        std::weak_ptr<boost::asio::ssl::context> WeakTls;
        {
            ProviderTesting::QuicFixture Fixture;WeakGeneration=Fixture.Pin;WeakTls=Fixture.Tls;
            auto Input=Fixture.Input("tuic");auto First=Input.Instances.front();
            First.Protocol={"first-socks","socks5","socks5",{}, {}};First.Tcp=true;
            auto Accounts=Prism::Testing::ProviderAccount(Prism::Account::Credential::Password("bind-password"));
            First.Authentication={Fixture.Pin,Accounts->Credentials,Accounts->Authenticator};
            Input.Instances.insert(Input.Instances.begin(),std::move(First));
            auto Services=Fixture.Services();Services.Quic.Listener.Executor=Context->Io.get_executor();
            Services.Quic.Listener.Socket=std::make_shared<boost::asio::ip::udp::socket>(Context->Io,
                boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),0));
            Services.Quic.Listener.Sender=Prism::Testing::Quic::MakeSender(Services.Quic.Listener.Socket);
            auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),std::move(Services));ASSERT_TRUE(Prepared);
            auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);Context->Io.stop();
            auto Failed=Frozen->Bind({});ASSERT_FALSE(Failed);
            EXPECT_EQ(Failed.error().Code,Prism::Contract::ProviderError::DispatchUnavailable);
            EXPECT_EQ(Failed.error().Instance,"quic-instance");EXPECT_EQ(Failed.error().Path,"Quic.Executor");
            auto Twice=Frozen->Bind({});ASSERT_FALSE(Twice);
            EXPECT_EQ(Twice.error().Code,Prism::Contract::ProviderError::AlreadyBound);
            Fixture.Io.run();EXPECT_EQ(Storage->Pending(),0U);
        }
        EXPECT_TRUE(WeakGeneration.expired());EXPECT_TRUE(WeakTls.expired());
        std::weak_ptr<Prism::Executor::ContextOwner> WeakContext=Context;
        Context.reset();EXPECT_TRUE(WeakContext.expired());
    }
    TEST(QuicProvider, StoppedDomainRetainsResourcesUntilOriginalExecutorRetirement)
    {
        ProviderTesting::QuicFixture Fixture;
        auto Storage=std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context=Prism::Executor::ContextOwner::Create(Storage);
        auto Services=Fixture.Services();Services.Quic.Listener.Executor=Context->Io.get_executor();
        Services.Quic.Listener.Socket=std::make_shared<boost::asio::ip::udp::socket>(Context->Io,
            boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),0));
        Services.Quic.Listener.Sender=Prism::Testing::Quic::MakeSender(Services.Quic.Listener.Socket);
        auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input("tuic"),std::move(Services));ASSERT_TRUE(Prepared);
        auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
        auto Factory=Bound->Find("quic-instance")->Quic();
        auto Request=Prism::Testing::Quic::MakeRequest({Factory,Fixture.Pin->Id(),"quic-instance",
            {std::byte{1}},{boost::asio::ip::address_v4::loopback(),4444},{}});
        auto Lease=Factory->Create(std::move(Request));ASSERT_TRUE(Lease);
        Context->Io.stop();Bound->Close();EXPECT_EQ(Storage->Pending(),1U);EXPECT_TRUE(Storage->IsSealed());
        bool Rejected=false;
        auto Check=[&]()->boost::asio::awaitable<void>
        {const auto DrainResult=co_await Bound->Drain();Rejected=!DrainResult;};
        boost::asio::co_spawn(Fixture.Io,Check(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});Fixture.Io.run();EXPECT_TRUE(Rejected);
        auto RejectedRequest=Prism::Testing::Quic::MakeRequest({Factory,Fixture.Pin->Id(),"quic-instance",
            {std::byte{2}},{boost::asio::ip::address_v4::loopback(),4445},{}});
        EXPECT_FALSE(Factory->Create(std::move(RejectedRequest)));
        Context->Io.restart();Storage->Retry();Context->Io.run();Storage->Collect();
        EXPECT_EQ(Storage->Pending(),0U);
        std::weak_ptr<Prism::Executor::ContextOwner> Weak=Context;
        Lease=std::unexpected(Prism::Contract::ProviderFailure{Prism::Contract::ProviderError::Cancelled,{},"Test"});
        Factory.reset();Bound=std::unexpected(Prism::Contract::ProviderFailure{
            Prism::Contract::ProviderError::Cancelled,{},"Test"});Context.reset();EXPECT_TRUE(Weak.expired());
    }
}
