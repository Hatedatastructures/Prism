/** @file Ss2022GatewayTest.cpp @brief 真实账户关联 raw UDP、bad auth/replay/多 key/取消退栈。 */
#include <gtest/gtest.h>
#include <chrono>
#include <latch>
#include <span>
#include <thread>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <TestSupport/Preview/AccountAdmissionAuthority.hpp>
#include <Preview/Boundary/Datagram/DatagramSender.hpp>
#include <Preview/Boundary/Datagram/DatagramClassifier.hpp>
#include <Preview/Net/Datagram/Egress.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
namespace
{
    namespace Net=boost::asio;namespace Ss=Preview::Shadowsocks2022;
    using Udp=Net::ip::udp;
    struct Fixture final
    {
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage=std::make_shared<Preview::Executor::ClosingStorage>();
        std::shared_ptr<Preview::Executor::ContextOwner> Context=Preview::Executor::ContextOwner::Create(Storage);
        Net::io_context& Io=Context->Io;
        Udp::socket Echo{Io,Udp::endpoint(Net::ip::address_v4::loopback(),0)};
        Udp::socket Client{Io,Udp::endpoint(Net::ip::address_v4::loopback(),0)};
        std::shared_ptr<Udp::socket> Listener=std::make_shared<Udp::socket>(Io,Udp::endpoint(Net::ip::address_v4::loopback(),0));
        Preview::Foundation::GenerationPin Pin=Preview::Testing::ProviderPin();
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState=std::make_shared<Preview::Foundation::GenerationUseState>();
        std::shared_ptr<Preview::Account::AccountStore> Accounts=std::make_shared<Preview::Account::AccountStore>();
        Preview::Account::CredentialIndexView Credentials;
        std::array<std::uint8_t,16> Key{},OtherKey{};
        std::shared_ptr<Ss::Binding> Binding;
        std::shared_ptr<Preview::Contract::RawDatagramIngress> Gateway;
        explicit Fixture(
            std::shared_ptr<Preview::Contract::DatagramEgress> Egress = {},
            std::chrono::milliseconds PeerIdleTimeout = std::chrono::milliseconds(60000))
        {
            Key.fill(0x32);OtherKey.fill(0x77);
            for(const auto& [Id,Bytes]:std::array{std::pair{1,Key},std::pair{2,OtherKey}})
            {
                std::vector<Preview::Account::CredentialMaterial> Materials;
                Materials.push_back({Preview::Account::CredentialScope{1U},{},
                    Preview::Account::Credential::Psk(
                        std::string_view(reinterpret_cast<const char*>(Bytes.data()),Bytes.size()))});
                auto Owned=std::make_shared<const Preview::Account::AccountMaterials>(
                    Preview::Account::AccountMaterials::CreateRequest{
                        Preview::AccountId{static_cast<std::uint64_t>(Id)},{},std::move(Materials)});
                auto Prepared=Accounts->PrepareUpsert(Preview::Account::AccountDefinition{
                    std::move(Owned),{.Quota={.MaxConnections=1}}});
                EXPECT_TRUE(Prepared);
                if(!Prepared)continue;
                EXPECT_TRUE(Accounts->Commit(*Prepared));
            }
            const auto Authority = Preview::Testing::AttachAccountAdmissionAuthority(
                Accounts->RuntimeRegistry());
            if (!Authority)throw std::runtime_error("account authority attachment failed");
            auto View=Accounts->CompileScope(Preview::Account::CredentialScope{1U});
            EXPECT_TRUE(View);
            if(View)Credentials=std::move(*View);
            auto Resolver=std::make_shared<Preview::Network::Dns::Resolver>(Io.get_executor(),Preview::Network::Dns::Config{});
            auto Prepared=Ss::Prepare({"raw",Pin,{.RawUdp=true,.PeerIdleTimeout=PeerIdleTimeout}},{Io.get_executor(),{Pin,Credentials,
                std::make_shared<Preview::DirectoryAuthenticator>(Credentials)},
                Egress?std::move(Egress):std::make_shared<Preview::Network::DatagramEgress>(Resolver),
                std::make_shared<Preview::Boundary::DatagramSender>(Listener),{}});
            if(!Prepared)throw std::runtime_error("gateway prepare failed");
            Binding=*Ss::Bind(std::move(*Prepared),{});Gateway=Binding->RawIngress();
        }
        auto Packet(const std::array<std::uint8_t,16>& Bytes,std::uint64_t Id=0)->Preview::Contract::DatagramPacket
        {
            const Ss::Address Target{Ss::AddressType::Ipv4,"127.0.0.1",Echo.local_endpoint().port()};
            const std::string Payload="account-linked-raw-udp";
            auto Wire=Ss::BuildUdpPacket(Ss::UdpBuildInput{Bytes,Id,&Target,
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(Payload.data()),Payload.size())});
            Preview::Contract::DatagramPacket Result{
                {reinterpret_cast<const std::byte*>(Wire.data()),
                    reinterpret_cast<const std::byte*>(Wire.data()+Wire.size())},
                Client.local_endpoint(),Id};
            auto Lease=UseState->Acquire();
            EXPECT_TRUE(Lease);
            if(Lease)Result.GenerationUse=std::move(*Lease);
            return Result;
        }
        /** @brief Peer 与 SS2022 客户端会话共同组成已有 raw association 身份。 */
        struct PeerIdentity final
        {
            Udp::endpoint Peer;
            std::array<std::uint8_t, Ss::SessionIdLen> ClientSession{};
        };
        auto PacketWithIdentity(const std::array<std::uint8_t,16>& Bytes,
            const PeerIdentity& Identity) -> Preview::Contract::DatagramPacket
        {
            const Ss::Address Target{Ss::AddressType::Ipv4,"127.0.0.1",Echo.local_endpoint().port()};
            const std::string Payload="account-linked-raw-udp";
            auto Wire=Ss::BuildUdpPacket(Ss::UdpBuildInput{Bytes,0,&Target,
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(Payload.data()),Payload.size()),
                std::span<const std::uint8_t>(Identity.ClientSession)});
            Preview::Contract::DatagramPacket Result{
                {reinterpret_cast<const std::byte*>(Wire.data()),
                    reinterpret_cast<const std::byte*>(Wire.data()+Wire.size())},
                Identity.Peer,0};
            auto Lease=UseState->Acquire();
            EXPECT_TRUE(Lease);
            if(Lease)Result.GenerationUse=std::move(*Lease);
            return Result;
        }

        /** @brief 为重放场景复制相同 wire 身份并取得独立 move-only 代次租约。 */
        auto CloneWithNewUseLease(const Preview::Contract::DatagramPacket& Original)
            -> Preview::Contract::DatagramPacket
        {
            Preview::Contract::DatagramPacket Copy{
                Original.Payload, Original.Peer, Original.Sequence};
            auto Lease = UseState->Acquire();
            EXPECT_TRUE(Lease);
            if (Lease) Copy.GenerationUse = std::move(*Lease);
            return Copy;
        }

        auto EchoOnce()->Net::awaitable<void>
        {
            std::array<std::byte,2048> Bytes{};Udp::endpoint Peer;
            const auto Size=co_await Echo.async_receive_from(Net::buffer(Bytes),Peer,Net::use_awaitable);
            EXPECT_EQ(std::string(reinterpret_cast<const char*>(Bytes.data()),Size),"account-linked-raw-udp");
            co_await Echo.async_send_to(Net::buffer(Bytes.data(),Size),Peer,Net::use_awaitable);
        }
        auto Receive(const std::array<std::uint8_t,16>& Bytes)->Net::awaitable<void>
        {
            std::array<std::uint8_t,4096> Wire{};Udp::endpoint Peer;
            const auto Size=co_await Client.async_receive_from(Net::buffer(Wire),Peer,Net::use_awaitable);
            Ss::Address Target;std::vector<std::uint8_t> Payload;std::uint8_t Type=0;
            EXPECT_EQ(Ss::ParseUdpPacket(Ss::UdpParseInput{Bytes,std::span(Wire).first(Size),&Target,&Payload,
                nullptr,nullptr,nullptr,&Type}),Preview::Error::None);
            EXPECT_EQ(Type,Ss::HeaderTypeServer);EXPECT_EQ(std::string(Payload.begin(),Payload.end()),"account-linked-raw-udp");
        }
        auto Run(Net::awaitable<void> Operation)->void
        {
            Net::co_spawn(Io,std::move(Operation),[](std::exception_ptr Error){EXPECT_FALSE(Error);});Io.run();
        }
    };
    TEST(Ss2022Gateway, AuthenticatedPacketRelaysAndBuildsServerPacket)
    {
        Fixture F;
        auto Run=[&]()->Net::awaitable<void>
        {
            using Net::experimental::awaitable_operators::operator&&;
            F.Gateway->Consume(F.Packet(F.Key));co_await(F.EchoOnce()&&F.Receive(F.Key));
            F.Binding->Close();EXPECT_TRUE(co_await F.Binding->Drain());
        };
        F.Run(Run());
    }
    TEST(Ss2022Gateway, BadAuthenticationDoesNotReachOutbound)
    {
        Fixture F;auto Bad=F.Packet(F.Key);Bad.Payload.back()^=std::byte{1};
        EXPECT_FALSE(F.Gateway->Matches({Bad.Payload,Bad.Peer,Bad.Sequence}));F.Gateway->Consume(std::move(Bad));
        auto Run=[&]()->Net::awaitable<void>
        {
            using Net::experimental::awaitable_operators::operator||;
            Net::steady_timer Timer(F.Io);Timer.expires_after(std::chrono::milliseconds(30));
            std::array<std::byte,1024> Buffer{};Udp::endpoint Peer;
            auto Result=co_await(F.Echo.async_receive_from(Net::buffer(Buffer),Peer,Net::use_awaitable)||Timer.async_wait(Net::use_awaitable));
            EXPECT_EQ(Result.index(),1);F.Binding->Close();EXPECT_TRUE(co_await F.Binding->Drain());
        };
        F.Run(Run());
    }
    TEST(Ss2022Gateway, ClaimsAuthenticatedQuicLikeUnknownCidBeforeQuicPacketGateway)
    {
        Fixture F;Preview::Boundary::DatagramClassifier Classifier;bool Found=false;
        for(std::uint64_t I=0;I<1024;++I)
        {
            const auto Packet=F.Packet(F.Key,I);const auto Classification=Classifier.Classify(Packet.Payload);
            if(Classification.Kind!=Preview::Boundary::DatagramKind::Quic
                || Classification.Route!=Preview::Boundary::DatagramRoute::UnknownCid)continue;
            EXPECT_TRUE(F.Gateway->Matches({Packet.Payload,Packet.Peer,Packet.Sequence}));
            auto TamperedPayload=Packet.Payload;
            TamperedPayload.back()^=std::byte{1};
            const auto TamperedClassification=Classifier.Classify(TamperedPayload);
            EXPECT_EQ(TamperedClassification.Kind,Classification.Kind);
            EXPECT_EQ(TamperedClassification.Route,Classification.Route);
            EXPECT_EQ(TamperedClassification.ConnectionIdBytes,Classification.ConnectionIdBytes);
            EXPECT_FALSE(F.Gateway->Matches({TamperedPayload,Packet.Peer,Packet.Sequence}));
            Found=true;
            break;
        }
        EXPECT_TRUE(Found);
        const std::vector<std::byte> Initial={std::byte{0xC0},std::byte{0},std::byte{0},std::byte{0},std::byte{1},std::byte{0},std::byte{0},std::byte{0}};
        EXPECT_FALSE(F.Gateway->Matches({Initial,{},{}}));
        F.Accounts->ForEach([](const auto& Record){EXPECT_EQ(Record->Runtime()->ActiveConnections(),0);});
        F.Binding->Close();
        auto Drain=[&]()->Net::awaitable<void>{EXPECT_TRUE(co_await F.Binding->Drain());};
        F.Run(Drain());
    }
    TEST(Ss2022Gateway, SecondAccountAndReplayUseRealEgressAndDrain)
    {
        Fixture F;auto Packet=F.Packet(F.OtherKey);
        auto Replay=F.CloneWithNewUseLease(Packet);
        auto Run=[&]()->Net::awaitable<void>
        {
            using Net::experimental::awaitable_operators::operator&&;
            using Net::experimental::awaitable_operators::operator||;
            F.Gateway->Consume(std::move(Packet));
            co_await(F.EchoOnce()&&F.Receive(F.OtherKey));
            F.Gateway->Consume(std::move(Replay));
            Net::steady_timer Timer(F.Io);
            Timer.expires_after(std::chrono::milliseconds(30));
            std::array<std::byte,1024> Buffer{};Udp::endpoint Peer;
            const auto Result=co_await(F.Echo.async_receive_from(Net::buffer(Buffer),Peer,Net::use_awaitable)||Timer.async_wait(Net::use_awaitable));
            EXPECT_EQ(Result.index(),1);F.Binding->Close();EXPECT_TRUE(co_await F.Binding->Drain());
        };
        F.Run(Run());
    }
    class PendingEgress final : public Preview::Contract::DatagramEgress
    {
    public:
        std::function<void()> Started;
        bool Finished{false};
        auto Exchange(Preview::Contract::DatagramExchangeRequest Request)
            ->Net::awaitable<Preview::Contract::DatagramExchangeResult> override
        {
            EXPECT_EQ(Request.AccountId,Preview::AccountId{1});
            Net::steady_timer Wait(co_await Net::this_coro::executor);Wait.expires_after(std::chrono::seconds(30));
            Started();boost::system::error_code ErrorValue;
            co_await Wait.async_wait(Net::redirect_error(Net::use_awaitable,ErrorValue));
            EXPECT_EQ(ErrorValue,Net::error::operation_aborted);Finished=true;
            co_return Preview::Contract::DatagramExchangeResult{};
        }
    };
    auto ExerciseExistingAssociationSnapshot(
        Fixture& F,
        const std::shared_ptr<PendingEgress>& Pending) -> Net::awaitable<void>
    {
        auto Started = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(F.Io, 1);
        Pending->Started = [Weak = std::weak_ptr(Started)]
        {
            if (const auto Signal = Weak.lock())
            {
                (void)Signal->try_send(boost::system::error_code{});
            }
        };
        Fixture::PeerIdentity Identity{.Peer = F.Client.local_endpoint()};
        Identity.ClientSession.fill(0x41U);
        auto Initial = F.PacketWithIdentity(F.Key, Identity);
        const Preview::Contract::DatagramView InitialView{
            Initial.Payload, Initial.Peer, Initial.Sequence};
        EXPECT_TRUE(F.Gateway->Matches(InitialView));
        EXPECT_FALSE(F.Gateway->MatchesExistingAssociation(InitialView));
        EXPECT_FALSE(F.Gateway->HasActiveAssociations());

        F.Gateway->Consume(std::move(Initial));
        co_await Started->async_receive(Net::use_awaitable);
        EXPECT_TRUE(F.Gateway->HasActiveAssociations());
        {
            auto Same = F.PacketWithIdentity(F.Key, Identity);
            const Preview::Contract::DatagramView SameView{Same.Payload, Same.Peer, Same.Sequence};
            EXPECT_TRUE(F.Gateway->MatchesExistingAssociation(SameView));

            auto OtherPeer = Identity;
            OtherPeer.Peer = Udp::endpoint(
                Net::ip::make_address_v4("127.0.0.2"), Identity.Peer.port());
            auto DifferentPeer = F.PacketWithIdentity(F.Key, OtherPeer);
            const Preview::Contract::DatagramView PeerView{
                DifferentPeer.Payload, DifferentPeer.Peer, DifferentPeer.Sequence};
            EXPECT_FALSE(F.Gateway->MatchesExistingAssociation(PeerView));

            auto OtherSession = Identity;
            OtherSession.ClientSession.fill(0x72U);
            auto DifferentSession = F.PacketWithIdentity(F.Key, OtherSession);
            const Preview::Contract::DatagramView SessionView{
                DifferentSession.Payload, DifferentSession.Peer, DifferentSession.Sequence};
            EXPECT_FALSE(F.Gateway->MatchesExistingAssociation(SessionView));

            auto OtherAccount = F.PacketWithIdentity(F.OtherKey, Identity);
            const Preview::Contract::DatagramView AccountView{
                OtherAccount.Payload, OtherAccount.Peer, OtherAccount.Sequence};
            EXPECT_FALSE(F.Gateway->MatchesExistingAssociation(AccountView));
        }
        Net::steady_timer Expiration(F.Io);
        Expiration.expires_after(std::chrono::milliseconds(20));
        co_await Expiration.async_wait(Net::use_awaitable);
        auto ReplacementIdentity = Identity;
        ReplacementIdentity.ClientSession.fill(0x72U);
        auto Replacement = F.PacketWithIdentity(F.Key, ReplacementIdentity);
        F.Gateway->Consume(std::move(Replacement));
        co_await Started->async_receive(Net::use_awaitable);
        {
            auto ExpiredSession = F.PacketWithIdentity(F.Key, Identity);
            const Preview::Contract::DatagramView ExpiredView{
                ExpiredSession.Payload, ExpiredSession.Peer, ExpiredSession.Sequence};
            EXPECT_FALSE(F.Gateway->MatchesExistingAssociation(ExpiredView));
            auto CurrentSession = F.PacketWithIdentity(F.Key, ReplacementIdentity);
            const Preview::Contract::DatagramView CurrentView{
                CurrentSession.Payload, CurrentSession.Peer, CurrentSession.Sequence};
            EXPECT_TRUE(F.Gateway->MatchesExistingAssociation(CurrentView));
        }
        EXPECT_EQ(F.UseState->Outstanding(), 1U);
        EXPECT_EQ(F.Accounts->FindById(Preview::AccountId{1})->Runtime()->ActiveConnections(), 1U);
        F.Binding->Close();
        const auto Drained = co_await F.Binding->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Pending->Finished);
        EXPECT_FALSE(F.Gateway->HasActiveAssociations());
        EXPECT_EQ(F.UseState->Outstanding(), 0U);
    }

    TEST(Ss2022Gateway, ExistingAssociationSnapshotMatchesIdentityAndExpiresOldSession)
    {
        auto Pending = std::make_shared<PendingEgress>();
        Fixture F(Pending, std::chrono::milliseconds(5));
        F.Run(ExerciseExistingAssociationSnapshot(F, Pending));
    }

    TEST(Ss2022Gateway, CloseCancelsEgressAndDrainWaitsForActualExitAndLeaseRelease)
    {
        auto Pending=std::make_shared<PendingEgress>();Fixture F(Pending);
        auto Started=std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(F.Io,1);
        Pending->Started=[Weak=std::weak_ptr(Started)]{if(auto Signal=Weak.lock())(void)Signal->try_send(boost::system::error_code{});};
        std::weak_ptr<const Preview::Foundation::GenerationLifetime> Weak=F.Pin;
        auto Run=[&]()->Net::awaitable<void>
        {
            F.Gateway->Consume(F.Packet(F.Key));co_await Started->async_receive(Net::use_awaitable);
            F.Accounts->ForEach([](const auto& Record){
                if(Record->AccountId()==Preview::AccountId{1})EXPECT_EQ(Record->Runtime()->ActiveConnections(),1);});
            F.Pin.reset();EXPECT_FALSE(Weak.expired());F.Binding->Close();EXPECT_FALSE(Pending->Finished);
            EXPECT_TRUE(co_await F.Binding->Drain());EXPECT_TRUE(Pending->Finished);
            F.Accounts->ForEach([](const auto& Record){EXPECT_EQ(Record->Runtime()->ActiveConnections(),0);});
            EXPECT_TRUE(Weak.expired());EXPECT_FALSE(F.Gateway->Matches({{}, {},0}));
        };
        F.Run(Run());

    }
    auto FinishPeerExchange(Fixture& F,std::latch& Ready)->Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        F.Gateway->Consume(F.Packet(F.Key));co_await(F.EchoOnce()&&F.Receive(F.Key));
        co_await Net::post(F.Io,Net::use_awaitable);
        co_await Net::post(F.Io,Net::use_awaitable);
        Ready.count_down();
    }
    TEST(Ss2022Gateway, CloseDrainAcrossExecutorsWaitsForFinalizerWithOnlyPeerLeaseRemaining)
    {
        Fixture F;Net::io_context Control;auto Work=Net::make_work_guard(F.Io);std::latch Ready(1);
        Net::co_spawn(F.Io,FinishPeerExchange(F,Ready),[&Ready](std::exception_ptr Failure)
        {if(Failure){ADD_FAILURE();Ready.count_down();}});
        std::thread Worker([&]{F.Io.run();});Ready.wait();
        F.Accounts->ForEach([](const auto& Record){if(Record->AccountId()==Preview::AccountId{1})EXPECT_EQ(Record->Runtime()->ActiveConnections(),1);});
        std::weak_ptr<const Preview::Foundation::GenerationLifetime> Weak=F.Pin;F.Pin.reset();
        F.Binding->Close();bool Drained=false;
        Net::co_spawn(Control,F.Binding->Drain(),[&](std::exception_ptr Error,
            std::expected<void,Preview::Fault::Failure> Result)
        {EXPECT_FALSE(Error);Drained=!Error && static_cast<bool>(Result);});Control.run();
        Work.reset();Worker.join();EXPECT_TRUE(Drained);EXPECT_TRUE(Weak.expired());
        F.Accounts->ForEach([](const auto& Record){EXPECT_EQ(Record->Runtime()->ActiveConnections(),0);});
    }
    TEST(Ss2022Gateway, SenderReturnsCancellationForListenerClosedOnItsOwnExecutor)
    {
        Net::io_context SocketIo,CallerIo;auto Socket=std::make_shared<Udp::socket>(SocketIo,Udp::endpoint(Udp::v4(),0));
        auto Sender=std::make_shared<Preview::Boundary::DatagramSender>(Socket);auto Work=Net::make_work_guard(SocketIo);
        std::latch Ready(1);Net::post(SocketIo,[&]{Socket->close();Ready.count_down();});
        std::thread Worker([&]{SocketIo.run();});Ready.wait();
        bool Completed=false;Preview::Contract::DatagramPacket Packet{{std::byte{0x12}},Udp::endpoint(Net::ip::address_v4::loopback(),9),0};
        Net::co_spawn(CallerIo,Sender->Send(std::move(Packet)),[&](std::exception_ptr Failure,boost::system::error_code Result)
        {EXPECT_FALSE(Failure);EXPECT_EQ(Result,Net::error::operation_aborted);Completed=true;});CallerIo.run();
        Work.reset();Worker.join();EXPECT_TRUE(Completed);
    }
    TEST(Ss2022Gateway, StoppedRawContextKeepsPeerLeaseAndGenerationUntilL1Retirement)
    {
        auto F=std::make_unique<Fixture>();auto Storage=F->Storage;auto UseState=F->UseState;
        std::weak_ptr<Preview::Executor::ContextOwner> WeakContext=F->Context;
        std::weak_ptr<const Preview::Foundation::GenerationLifetime> WeakPin=F->Pin;
        auto Exchange=[&]()->Net::awaitable<void>
        {
            using Net::experimental::awaitable_operators::operator&&;
            F->Gateway->Consume(F->Packet(F->Key));co_await(F->EchoOnce()&&F->Receive(F->Key));
            co_await Net::post(F->Io,Net::use_awaitable);co_await Net::post(F->Io,Net::use_awaitable);
        };
        Net::co_spawn(F->Io,Exchange(),[&](std::exception_ptr Error){EXPECT_FALSE(Error);F->Io.stop();});
        F->Io.run();ASSERT_TRUE(F->Io.stopped());
        EXPECT_EQ(UseState->Outstanding(),1U);
        auto Runtime=F->Accounts->FindById(Preview::AccountId{1})->Runtime();EXPECT_EQ(Runtime->ActiveConnections(),1);
        F->Pin.reset();F->Binding->Close();EXPECT_EQ(Storage->Pending(),1);EXPECT_TRUE(Storage->IsSealed());
        EXPECT_EQ(UseState->Outstanding(),1U);
        Net::io_context Control;bool Failed=false;
        Net::co_spawn(Control,F->Binding->Drain(),[&](std::exception_ptr Error,
            std::expected<void,Preview::Fault::Failure> Result)
        {Failed=bool(Error) || !Result;});Control.run();
        EXPECT_TRUE(Failed);F.reset();EXPECT_FALSE(WeakPin.expired());EXPECT_FALSE(WeakContext.expired());
        EXPECT_EQ(Runtime->ActiveConnections(),1);auto Context=WeakContext.lock();Context->Io.restart();
        Storage->Retry();Context->Io.run();Storage->Collect();EXPECT_EQ(Storage->Pending(),0);
        EXPECT_EQ(Runtime->ActiveConnections(),0);EXPECT_EQ(UseState->Outstanding(),0U);EXPECT_TRUE(WeakPin.expired());Context.reset();EXPECT_TRUE(WeakContext.expired());
    }
}
