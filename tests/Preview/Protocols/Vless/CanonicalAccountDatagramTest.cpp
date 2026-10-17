/** @file CanonicalAccountDatagramTest.cpp @brief 真实账户数据报观察与失败隔离。 */
#include <gtest/gtest.h>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Preview/DiagnoseTestEnvironment.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <TestSupport/Preview/ProtocolIngressBindings.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <expected>
#include <fstream>

namespace
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;
    using DatagramRunResult = std::expected<void, Preview::Fault::Failure>;
    using Done = Net::experimental::channel<void(boost::system::error_code, Preview::Fault::Failure)>;
    /**
     * @brief 用真实有界字节池组装协议接入输入。
     * @param Inbound 由测试协程移交的入站传输 owner。
     * @param Metadata 本用例的请求元数据快照。
     * @return 按值移交的完整接入输入。
     */
    [[nodiscard]] auto MakeStreamAcceptInput(Preview::SharedTransmission Inbound,
        Preview::Contract::RequestMetadata Metadata) -> Preview::Contract::StreamAcceptInput
    {
        return {std::move(Inbound), std::move(Metadata),
            std::make_shared<Preview::Memory::BytePool>(Preview::Memory::BytePoolOptions{.BlockCount = 8})};
    }
    class Traffic final : public Preview::Foundation::TrafficSink
    {
    public:
        explicit Traffic(bool Throw) : Throw_(Throw) {}
        auto Report(Preview::Foundation::TrafficEvent Event) noexcept -> void override
        {
            ++Calls;
            if (EventCount < Events.size())
            {
                Events[EventCount++] = Event;
            }
            if (Event.Kind == Preview::Foundation::TrafficEventKind::Bytes)
            {
                ++ByteEvents;
                Uploaded += Event.Up;
                Downloaded += Event.Down;
            }
            else if (Event.Kind == Preview::Foundation::TrafficEventKind::Completed)
            {
                ++CompletedEvents;
            }
            if (Throw_) ObservationFailure = true;
        }
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Preview::Fault::Failure>{}; }
        int Calls{0};
        int ByteEvents{0}, CompletedEvents{0};
        std::array<Preview::Foundation::TrafficEvent, 3> Events{};
        std::size_t EventCount{0};
        std::size_t Uploaded{0}, Downloaded{0};
        bool ObservationFailure{false};
    private:
        bool Throw_;
    };
    struct AccountRun final
    {
        std::shared_ptr<Preview::Vless::IngressFactory> Factory;
        std::shared_ptr<Preview::Contract::DatagramSession> Owner;
        Preview::SharedTransmission Inbound;
        std::shared_ptr<const Preview::Account::AccountBinding> Record;
        std::shared_ptr<Done> Completion;
        Preview::AccountId Account{};
        std::size_t ConnectionsDuringRun{0};
    };
    auto RunOwner(std::shared_ptr<AccountRun> State, Preview::SharedTransmission Carrier)
        -> Net::awaitable<DatagramRunResult>
    {
        Preview::Contract::RequestMetadata Metadata;
        Metadata.SourceIp = "127.0.0.1";
        auto Input = MakeStreamAcceptInput(std::move(Carrier), std::move(Metadata));
        auto Accepted = co_await State->Factory->Accept(std::move(Input));
        if (!Accepted)
            co_return std::unexpected(Accepted.error());
        State->Inbound = Accepted->Transport();
        State->Account = Accepted->AccountId;
        State->ConnectionsDuringRun = State->Record->Runtime()->ActiveConnections();
        if (!Accepted->Datagram())
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::NotSupported});
        State->Owner = Accepted->Datagram()->Session;
        co_return co_await State->Owner->Run();
    }
    auto EchoOnce(const std::shared_ptr<Udp::socket>& Socket) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 16> Buffer{};
        Udp::endpoint Peer;
        const auto Size = co_await Socket->async_receive_from(Net::buffer(Buffer), Peer, Net::use_awaitable);
        co_await Socket->async_send_to(Net::buffer(Buffer.data(), Size), Peer, Net::use_awaitable);
    }
    class AccountScenario final
    {
    public:
        explicit AccountScenario(bool ThrowObservation)
            : Environment("account-datagram"), Sink(std::make_shared<Traffic>(ThrowObservation)),
              ThrowObservation_(ThrowObservation)
        { Prepare(); }

        auto Install() -> bool { return Environment.Install().has_value(); }

        auto Run() -> Net::awaitable<void>
        {
            Net::co_spawn(Io, EchoOnce(Echo), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
            Net::co_spawn(Io, RunOwner(State, std::move(Server)),
                [Value = State](std::exception_ptr Exception, DatagramRunResult Result)
                {
                    const auto Failure = Exception ? Preview::Fault::Failure{Preview::Fault::Code::IoError}
                        : Result ? Preview::Fault::Failure{} : Result.error();
                    (void)Value->Completion->try_send(boost::system::error_code{}, Failure);
                });
            Preview::Vless::ClientConfig ClientConfig;
            ClientConfig.uuid = Config.uuid;
            auto ConnectResult = co_await Preview::Vless::Connect(Preview::Vless::ConnectParameters{
                Client, ClientConfig,
                {Preview::Vless::AddressType::Domain, "x", 53}, Preview::Vless::Command::Udp});
            EXPECT_TRUE(ConnectResult);
            if (ConnectResult) EXPECT_TRUE(*ConnectResult);
            if (!ConnectResult || !*ConnectResult)
            {
                ADD_FAILURE() << "authenticated association was not created";
                State->Factory->Close();
                const auto Retired = co_await State->Factory->Drain();
                EXPECT_TRUE(Retired);
                EXPECT_TRUE(State->Factory->IsRetired());
                co_return;
            }
            auto Connection = std::move(*ConnectResult);
            const std::array<std::uint8_t, 6> Wire{0, 4, 'a', 'c', 'c', 't'};
            const auto WriteResult = co_await Connection->WriteExact(std::as_bytes(std::span(Wire)));
            EXPECT_FALSE(WriteResult.Failure.Failed());
            EXPECT_EQ(WriteResult.Bytes, Wire.size());
            const auto HalfClose = co_await Connection->WriteShutdown();
            EXPECT_TRUE(HalfClose);
            std::array<std::uint8_t, 32> Response{};
            const auto ReadFailed = co_await Connection->ReadExact(std::span(Response).first(6));
            EXPECT_FALSE(ReadFailed);
            EXPECT_EQ(std::string(Response.begin() + 2, Response.begin() + 6), "acct");
            const auto Result = co_await State->Completion->async_receive(Net::use_awaitable);
            EXPECT_EQ(Result.Code, Preview::Fault::Code::Success);

            State->Owner->Close();
            const auto OwnerRetired = co_await State->Owner->Activity()->Drain();
            EXPECT_TRUE(OwnerRetired)
                << (OwnerRetired ? 0 : static_cast<int>(OwnerRetired.error().Code));
            State->Factory->Close();
            const auto Retired = co_await State->Factory->Drain();
            EXPECT_TRUE(Retired) << (Retired ? 0 : static_cast<int>(Retired.error().Code));
            EXPECT_TRUE(State->Factory->IsRetired());
            EXPECT_FALSE(State->Inbound->NextLayer()->IsOpen());
            Client->Close();
            Echo->close();
        }

        auto Check() -> void
        {
            EXPECT_EQ(State->Account, Preview::AccountId{901});
            EXPECT_EQ(State->ConnectionsDuringRun, 1U);
            EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
            ASSERT_EQ(Sink->Calls, 3);
            ASSERT_EQ(Sink->EventCount, 3U);
            EXPECT_EQ(Sink->ByteEvents, 2);
            EXPECT_EQ(Sink->CompletedEvents, 1);
            EXPECT_EQ(Sink->Uploaded, 4U);
            EXPECT_EQ(Sink->Downloaded, 4U);
            const auto &Identity = Sink->Events[0];
            std::size_t CompletedIndex = Sink->EventCount;
            for (std::size_t Index = 0; Index < Sink->EventCount; ++Index)
            {
                const auto &Event = Sink->Events[Index];
                EXPECT_EQ(Event.Account, Preview::AccountId{901});
                EXPECT_EQ(Event.Generation, Identity.Generation);
                EXPECT_EQ(Event.Worker, Identity.Worker);
                EXPECT_EQ(Event.Session, Identity.Session);
                EXPECT_EQ(Event.Stream, Identity.Stream);
                EXPECT_EQ(Event.Task, Identity.Task);
                if (Event.Kind == Preview::Foundation::TrafficEventKind::Completed)
                {
                    CompletedIndex = Index;
                }
            }
            ASSERT_LT(CompletedIndex, Sink->EventCount);
            EXPECT_EQ(Sink->Events[CompletedIndex].Up, 0U);
            EXPECT_EQ(Sink->Events[CompletedIndex].Down, 0U);
            EXPECT_EQ(Sink->ObservationFailure, ThrowObservation_);
            EXPECT_EQ(Environment.Runtime().Shutdown().Status, Preview::Diagnose::SubmissionStatus::Closed);
            std::ifstream Input(Environment.Configuration().Logging.Directory /
                Environment.Configuration().Logging.FileName, std::ios::binary);
            const std::string Contents{std::istreambuf_iterator<char>{Input}, std::istreambuf_iterator<char>{}};
            const auto Request = Contents.find("Request SourceIp=127.0.0.1 Target=x:53 User=901");
            EXPECT_NE(Request, std::string::npos) << Contents;
            EXPECT_EQ(Contents.find("Request SourceIp=", Request == std::string::npos ? 0 : Request + 1), std::string::npos);
            EXPECT_EQ(Contents.find("000102030405060708090a0b0c0d0e0f"), std::string::npos);
        }

        Net::io_context Io;

    private:
        auto Prepare() -> void
        {
            Environment.Configuration().Mode = Preview::Diagnose::RenderMode::Structured;
            Environment.Configuration().Logging.Level = Preview::Diagnose::LogLevel::Info;
            Directory = Preview::Testing::ProviderAccount(
                Preview::Account::Credential::Uuid({std::byte{0}, std::byte{1}, std::byte{2}, std::byte{3},
                    std::byte{4}, std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}, std::byte{9}, std::byte{10},
                    std::byte{11}, std::byte{12}, std::byte{13}, std::byte{14}, std::byte{15}}),
                Preview::AccountId{901}, {.MaxConnections = 1});
            Record = Directory->Store->FindById(Preview::AccountId{901});
            ASSERT_TRUE(Record);
            Echo = std::make_shared<Udp::socket>(Io,
                Udp::endpoint(Net::ip::address_v4::loopback(), 0));
            Preview::Contract::DatagramServices Services;
            Services.IdleTimeout = std::chrono::milliseconds(20);
            Services.Traffic = Sink;
            Services.Resolve = [Endpoint = Echo->local_endpoint()](Preview::Network::Target)
                -> Net::awaitable<std::expected<Udp::endpoint, Preview::Fault::Failure>>
            { co_return Endpoint; };
            Config.uuid = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            Config.EnableUdp = true;
        Config.AuthenticatorOwner = std::make_shared<Preview::DirectoryAuthenticator>(Directory->Credentials);
            State = std::make_shared<AccountRun>();
            State->Record = Record;
            State->Factory = Preview::Testing::MakeVlessIngress(Config,
                Preview::Testing::ProtocolIngressResources{
                    Services, Preview::Testing::MakeProtocolIngressUseState(), Io.get_executor()},
                Preview::Vless::IngressRoute{});
            State->Completion = std::make_shared<Done>(Io, 1);
            auto [ClientValue, ServerValue] = Preview::MakeMemoryPair(Io.get_executor());
            Client = std::make_shared<Preview::MemoryStream>(std::move(ClientValue));
            Server = std::make_shared<Preview::MemoryStream>(std::move(ServerValue));
        }

        Preview::TestSupport::DiagnoseTestEnvironment Environment;
        std::shared_ptr<const Preview::Account::AccountBinding> Record;
        std::shared_ptr<Preview::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Udp::socket> Echo;
        std::shared_ptr<Traffic> Sink;
        Preview::Vless::ServerConfig Config;
        std::shared_ptr<AccountRun> State;
        std::shared_ptr<Preview::MemoryStream> Client, Server;
        bool ThrowObservation_{false};
    };

    auto CheckAccountObservation(bool ThrowObservation) -> void
    {
        AccountScenario Scenario(ThrowObservation);
        ASSERT_TRUE(Scenario.Install());
        Preview::Testing::RunCoro(Scenario.Io, [&Scenario]() -> Net::awaitable<void>
        { co_await Scenario.Run(); });
        Scenario.Check();
    }
    TEST(CanonicalAccountDatagram, EmptyDisplayIdentityUsesActualAccountId) { CheckAccountObservation(false); }
    TEST(CanonicalAccountDatagram, ThrowingObservationPreservesPayloadAndLeaseRelease) { CheckAccountObservation(true); }
}
