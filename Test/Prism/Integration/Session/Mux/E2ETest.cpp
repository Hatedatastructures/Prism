/** @file E2ETest.cpp @brief 当前 Runtime listener 消费协议正式 mux owner 的真实转发与半关闭。 */
#include <TestSupport/Fixtures/MuxRoot.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Prism/Protocol/Ingress.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Test/Prism/Runtime/Session/AdmissionSupport.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
namespace
{
    namespace F=Prism::Testing::MuxRoot;
    namespace Net=boost::asio;
    using Smux=Prism::Mux::Smux::Client<>;
    TEST(MuxRootRuntime, FactoryPublishesOwnerBeforeRun)
    {
        Net::io_context Io;auto [C,S]=Prism::MakeMemoryPair(Io.get_executor());
        auto Transport=std::make_shared<Prism::MemoryStream>(std::move(S));
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Wire=Prism::Mux::Mode::Smux,
            .Services={.Egress=Prism::Testing::UnavailableEgress()},
            .GenerationUseState=UseState});
        std::weak_ptr<Prism::Contract::MuxSession> Weak;
        bool Done=false;std::exception_ptr Failure;
        const auto Operation=[&]()->Net::awaitable<void>
        {
            auto Created = co_await F::CreateRoot(Binding, Transport);
            EXPECT_TRUE(Created);
            if (!Created) co_return;
            Weak = Created->Session;
            Binding->Close();Binding->Close();EXPECT_TRUE(co_await Binding->Drain());
            Created->Plane = {};
            Created->Session.reset();C.Close();Done=true;
        };
        Net::co_spawn(Io,Operation(),[&](std::exception_ptr Error){Failure=Error;});Io.run();
        EXPECT_TRUE(Done);EXPECT_FALSE(Failure);EXPECT_FALSE(Transport->IsOpen());EXPECT_TRUE(Weak.expired());
    }
    auto MakeMuxRuntimeSession(std::shared_ptr<F::State> S,
        std::shared_ptr<Prism::Trojan::IngressFactory> Factory,
        bool& RuntimeDialCalled) -> std::shared_ptr<Prism::Runtime::Session>
    {
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = S->Bytes;
        Options.Services->GenerationUseState = S->UseState;
        Options.Services->AcceptProtocol = std::move(Factory);
        Options.Services->Dial = [&RuntimeDialCalled](const Prism::Network::Target&)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            RuntimeDialCalled = true;
            co_return std::unexpected(Prism::Fault::Failure{F::Code::IoError});
        };
        return std::make_shared<Prism::Runtime::Session>(std::move(Options));
    }

    auto RunMuxSessionScenario(std::shared_ptr<F::State> S) -> Net::awaitable<void>
    {
        Prism::Trojan::ServerConfig Configuration;
        Configuration.Password = std::string(F::Password);
        Configuration.EnableMux = true;
        auto Factory = Prism::Testing::MakeTrojanIngress(
            std::move(Configuration), Prism::Testing::ProtocolIngressResources{
                .Datagrams = {}, .UseState = S->UseState, .Executor = S->Executor},
            Prism::Trojan::IngressRoute{.Mux = S->Binding});
        bool RuntimeDialCalled=false;
        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor=S->Executor;
        ListenerOptions.Publication=Prism::Testing::Runtime::MakeListenerTestPublication(
            Prism::GenerationId{7});
        ListenerOptions.Factory=
            [Factory,&RuntimeDialCalled,S](Prism::Runtime::SessionAdmission)
                ->std::shared_ptr<Prism::Runtime::Session>
        {
            return MakeMuxRuntimeSession(S, Factory, RuntimeDialCalled);
        };
        Prism::Runtime::TcpListener Listener(std::move(ListenerOptions));
        EXPECT_EQ(co_await Listener.Start(F::Tcp::endpoint(F::Tcp::v4(),0)),F::Code::Success);
        F::Tcp::socket Socket(S->Executor);co_await Socket.async_connect(
            F::Tcp::endpoint(Net::ip::address_v4::loopback(),Listener.LocalEndpoint().port()),Net::use_awaitable);
        auto Raw=std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        const auto Auth=Prism::Trojan::BuildRequest(Prism::Trojan::Credential(F::Password),Prism::Trojan::Command::Mux,
            Prism::Trojan::Address{Prism::Trojan::AddressType::Ipv4,"127.0.0.1",80});
        std::error_code Error;const auto WriteAuth=co_await Raw->WriteExact(std::as_bytes(std::span(Auth)));Error=Prism::Fault::ToNative(WriteAuth.Failure);EXPECT_FALSE(Error);
        const std::array<std::byte,2> Envelope{std::byte{0},std::byte{0}};
        const auto WriteEnvelope=co_await Raw->WriteExact(Envelope);Error=Prism::Fault::ToNative(WriteEnvelope.Failure);EXPECT_FALSE(Error);
        auto Client=std::make_shared<Smux>();EXPECT_TRUE(Client->Connect(Raw));
        auto Stream=co_await F::RoundTrip(S,Client);EXPECT_TRUE(Stream);
        Prism::Contract::Ingress::StreamIdentity StreamIdentity;
        bool StreamVisible=false;
        if(Stream)
        {
            const auto Sessions=Listener.Registry().Snapshot();
            if(!Sessions->empty())
            {
                const auto& Parent=Sessions->begin()->second;
                const auto Typed=std::static_pointer_cast<Prism::Mux::StreamTransmission>(Stream);
                StreamIdentity={Prism::SessionId{Parent.Id},Parent.Worker,Parent.Generation,
                    Prism::StreamId{Typed->Handle()->Id()}};
                const auto Lookup=Listener.Registry().FindStream(StreamIdentity);
                StreamVisible=Lookup.Status==Prism::Contract::Ingress::StreamCatalogStatus::Found&&
                    Lookup.Value.Identity==StreamIdentity&&Lookup.Value.State==Prism::Contract::Ingress::StreamState::Active;
            }
        }
        EXPECT_TRUE(StreamVisible);
        if(Stream)
        {
            (void)co_await Stream->WriteShutdown();std::array<std::byte,1> Tail{};
            const auto Read=co_await Stream->ReadSome(Tail);Error=Prism::Fault::ToNative(Read.Failure);const auto Count=Read.Bytes;EXPECT_EQ(Count,0U);
        }
        EXPECT_TRUE(co_await F::Wait(S->Reported));
        const auto Retired=Listener.Registry().FindStream(StreamIdentity);
        EXPECT_EQ(Retired.Status,Prism::Contract::Ingress::StreamCatalogStatus::NotFound);
        co_await F::Close(Client);co_await Listener.Shutdown();
        EXPECT_FALSE(RuntimeDialCalled);EXPECT_EQ(S->Dials,1U);EXPECT_EQ(S->Reports.size(),1U);
        if(!S->Reports.empty())
        {
            EXPECT_EQ(S->Reports[0].Relay.Total[0],F::Literal.size());EXPECT_EQ(S->Reports[0].Relay.Total[1],F::Literal.size());
            EXPECT_TRUE(S->Reports[0].Identity.SessionId);EXPECT_TRUE(S->Reports[0].Identity.TaskId);
        }
        co_await F::Finish(S);
    }

    TEST(MuxMiddleware, SessionWithMuxStillDialsAndRelays)
    {
        F::Scenario(Prism::Mux::Mode::Smux, RunMuxSessionScenario);
    }
}
