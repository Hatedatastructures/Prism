/** @file MuxE2ETest.cpp @brief 当前 Runtime listener 消费协议正式 mux owner 的真实转发与半关闭。 */
#include <TestSupport/Fixtures/MuxRoot.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Contract/Ingress/StreamCatalog.hpp>
namespace
{
    namespace F=Preview::Testing::MuxRoot;
    namespace Net=boost::asio;
    using Smux=Preview::Mux::Smux::Client<>;
    TEST(MuxRootRuntime, FactoryPublishesOwnerBeforeRun)
    {
        Net::io_context Io;auto [C,S]=Preview::MakeMemoryPair(Io.get_executor());
        auto Transport=std::make_shared<Preview::MemoryStream>(std::move(S));
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Binding = std::make_shared<Preview::Mux::RootBinding>(Preview::Mux::RootOptions{
            .Wire=Preview::Mux::Mode::Smux,
            .Services={.Egress=Preview::Testing::UnavailableEgress()},
            .GenerationUseState=UseState});
        std::weak_ptr<Preview::Contract::MuxSession> Weak;
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
    auto RunMuxSessionScenario(std::shared_ptr<F::State> S) -> Net::awaitable<void>
    {
        Preview::Trojan::ServerConfig Configuration;
        Configuration.AuthenticatorOwner=S->Accounts->Authenticator;
        auto Factory=std::make_shared<Preview::Trojan::IngressFactory>(Preview::Trojan::IngressOptions{
            .Configuration=std::move(Configuration),.Mux=S->Binding});
        bool RuntimeDialCalled=false;
        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor=S->Executor;
        ListenerOptions.Publication=Preview::Testing::Runtime::MakeListenerTestPublication(
            Preview::GenerationId{7});
        ListenerOptions.Factory=
            [Factory,&RuntimeDialCalled,S](Preview::Runtime::SessionAdmission)
                ->std::shared_ptr<Preview::Runtime::Session>
        {
            Preview::Runtime::SessionOptions Options;Options.Services->Bytes=S->Bytes;
            Options.Services->AcceptProtocol=Factory;
            Options.Services->Dial=[&RuntimeDialCalled](const Preview::Network::Target&)
                ->Net::awaitable<std::expected<Preview::SharedTransmission,Preview::Fault::Failure>>
            { RuntimeDialCalled=true;co_return std::unexpected(Preview::Fault::Failure{F::Code::IoError}); };
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        };
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));
        EXPECT_EQ(co_await Listener.Start(F::Tcp::endpoint(F::Tcp::v4(),0)),F::Code::Success);
        F::Tcp::socket Socket(S->Executor);co_await Socket.async_connect(
            F::Tcp::endpoint(Net::ip::address_v4::loopback(),Listener.LocalEndpoint().port()),Net::use_awaitable);
        auto Raw=std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        const auto Auth=Preview::Trojan::BuildRequest(Preview::Trojan::Credential(F::Password),Preview::Trojan::Command::Mux,
            Preview::Trojan::Address{Preview::Trojan::AddressType::Ipv4,"127.0.0.1",80});
        std::error_code Error;const auto WriteAuth=co_await Raw->WriteExact(std::as_bytes(std::span(Auth)));Error=Preview::Fault::ToNative(WriteAuth.Failure);EXPECT_FALSE(Error);
        const std::array<std::byte,2> Envelope{std::byte{0},std::byte{0}};
        const auto WriteEnvelope=co_await Raw->WriteExact(Envelope);Error=Preview::Fault::ToNative(WriteEnvelope.Failure);EXPECT_FALSE(Error);
        auto Client=std::make_shared<Smux>();EXPECT_TRUE(Client->Connect(Raw));
        auto Stream=co_await F::RoundTrip(S,Client);EXPECT_TRUE(Stream);
        Preview::Contract::Ingress::StreamIdentity StreamIdentity;
        bool StreamVisible=false;
        if(Stream)
        {
            const auto Sessions=Listener.Registry().Snapshot();
            if(!Sessions->empty())
            {
                const auto& Parent=Sessions->begin()->second;
                const auto Typed=std::static_pointer_cast<Preview::Mux::StreamTransmission>(Stream);
                StreamIdentity={Preview::SessionId{Parent.Id},Parent.Worker,Parent.Generation,
                    Preview::StreamId{Typed->Handle()->Id()}};
                const auto Lookup=Listener.Registry().FindStream(StreamIdentity);
                StreamVisible=Lookup.Status==Preview::Contract::Ingress::StreamCatalogStatus::Found&&
                    Lookup.Value.Identity==StreamIdentity&&Lookup.Value.State==Preview::Contract::Ingress::StreamState::Active;
            }
        }
        EXPECT_TRUE(StreamVisible);
        if(Stream)
        {
            (void)co_await Stream->WriteShutdown();std::array<std::byte,1> Tail{};
            const auto Read=co_await Stream->ReadSome(Tail);Error=Preview::Fault::ToNative(Read.Failure);const auto Count=Read.Bytes;EXPECT_EQ(Count,0U);
        }
        EXPECT_TRUE(co_await F::Wait(S->Reported));
        const auto Retired=Listener.Registry().FindStream(StreamIdentity);
        EXPECT_EQ(Retired.Status,Preview::Contract::Ingress::StreamCatalogStatus::NotFound);
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
        F::Scenario(Preview::Mux::Mode::Smux, RunMuxSessionScenario);
    }
}
