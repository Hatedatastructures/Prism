/** @file XudpSessionOwnerTest.cpp @brief 实际 VLESS 认证后的独立关联 wire 行为。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <Prism/Account/Account.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Vless/Xudp/RootSession.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
#include <array>
#include <optional>
#include <system_error>


namespace
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;
    constexpr std::string_view Payload{"A4-XUDP-LITERAL"};
    /**
     * @brief 构造携带真实有界字节池的协议接入输入。
     * @param Inbound 由测试 fixture 移交的入站传输 owner。
     * @return 包含入站传输、空元数据和新建字节池的输入。
     */
    [[nodiscard]] auto MakeStreamAcceptInput(Prism::SharedTransmission Inbound)
        -> Prism::Contract::StreamAcceptInput
    {
        return {std::move(Inbound), {}, std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8})};
    }
    enum class Lifecycle { Ordinary, DnsDeadline, DnsCancel, DnsEnd, Quota, FamilySwitch, UnknownKeep };
    struct Options { bool HeadOfLine{false},MultipleReplies{false}; Lifecycle Action{Lifecycle::Ordinary}; };
    struct Result
    {
        bool Authenticated{false}, First{false}, Second{false}, SurvivedEnd{false};
        bool RootCompleted{false}, TimedOut{false}, DnsExited{false}, DnsWasPending{false}, Rejected{false};
        bool Ipv6Ready{false};
        bool OwnerWasActiveDuringTraffic{false}, OwnerWasActiveDuringDns{false};
        bool OwnerRetiredDuringTraffic{false}, OwnerRetiredDuringDns{false};
        bool OwnerRetiredAfterRun{false}, FactoryRetiredAfterRun{false}, RunFailed{false};
        std::size_t GenerationUsesDuringRun{0}, GenerationUsesDuringDns{0}, GenerationUsesAfterRun{0};
        std::size_t ResolveCalls{0}, AfterDrainStreams{0};
        std::size_t EchoReceived{0}, Echo6Received{0}, StreamsAfterFirst{0}, Reports{0}, Up{0}, Down{0};
        bool UnknownKeepRejected{false};
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        std::weak_ptr<Prism::Contract::MuxSession> WeakOwner;
        std::exception_ptr Failure;
    };
    struct Fixture final : Result
    {
        explicit Fixture(Net::any_io_executor Ex,bool Quota=false,bool NeedIpv6=false) : Echo(Ex, Udp::endpoint(Udp::v4(), 0)),
            Echo6(Ex), Silent(Ex, Udp::endpoint(Udp::v4(), 0)),
            DnsSocket(Ex,Udp::endpoint(Udp::v4(),0)), Deadline(Ex), Finished(Ex,8)
        {
            auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Ex);
            Client = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
            Server = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
            Uuid.fill(0x41);
            std::array<std::byte, 16> Credential{};
            Credential.fill(std::byte{0x41});
            Directory = Prism::Testing::ProviderAccount(
                Prism::Account::Credential::Uuid(Credential), Prism::AccountId{4401},
                {.MaxConnections = 1, .MaxStreams = Quota?1U:2U});
            Record = Directory->Store->FindById(Prism::AccountId{4401});
            GenerationUse = std::make_shared<Prism::Foundation::GenerationUseState>();
            EXPECT_TRUE(Record);
            if (NeedIpv6)
            {
                boost::system::error_code Error;
                Echo6.open(Udp::v6(), Error);
                if (!Error) Echo6.bind(Udp::endpoint(Udp::v6(), 0), Error);
                Ipv6Ready = !Error;
            }
        }
        auto Close() -> void
        {
            RootCancel.emit(Net::cancellation_type::all);
            Client->Close();
            if (Server) Server->Close();
            if (Owner) { Owner->Cancel(); Owner->Close(); }
            boost::system::error_code Ignored;
            Echo.close(Ignored); Echo6.close(Ignored); Silent.close(Ignored); DnsSocket.close(Ignored); Deadline.cancel();
        }
        Udp::socket Echo, Echo6, Silent, DnsSocket;
        Net::experimental::channel<void(boost::system::error_code)> Finished;
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver;
        Net::steady_timer Deadline;
        Net::cancellation_signal RootCancel;
        Prism::SharedTransmission Client, Server;
        std::shared_ptr<Prism::Contract::MuxSession> Owner;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUse;
        std::array<std::uint8_t, 16> Uuid{};
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        bool HeadOfLine{false}, MultipleReplies{false};
        Lifecycle Action{Lifecycle::Ordinary};
    };
    class Traffic final : public Prism::Foundation::TrafficSink
    {
    public:
        explicit Traffic(std::weak_ptr<Fixture> Value) : Value_(std::move(Value)) {}
        auto Report(Prism::Foundation::TrafficEvent Event) noexcept -> void override
        {
            if (const auto S = Value_.lock())
            {
                const auto Uses = S->GenerationUse->Outstanding();
                if (Uses > S->GenerationUsesDuringRun) S->GenerationUsesDuringRun = Uses;
                if (S->Owner)
                {
                    const bool Retired = S->Owner->IsRetired();
                    S->OwnerRetiredDuringTraffic = S->OwnerRetiredDuringTraffic || Retired;
                    if (!Retired) S->OwnerWasActiveDuringTraffic = true;
                }
                S->Up += Event.Up;
                S->Down += Event.Down;
                if (Event.Kind == Prism::Foundation::TrafficEventKind::Completed)
                {
                    ++S->Reports;
                    (void)S->Finished.try_send(boost::system::error_code{});
                }
            }
        }
        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }
    private: std::weak_ptr<Fixture> Value_;
    };
    struct TaskDrainProbe final
    {
        bool Submitted{false}, DrainSucceeded{false}, PhysicallyRetired{false};
        Prism::Fault::Failure FirstFailure{};
        Prism::Lifecycle::TaskStats Stats{};
    };
    auto FailTrackedTask() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_return std::unexpected(Prism::Fault::Failure{
            Prism::Fault::Code::IoError, std::make_error_code(std::errc::io_error)});
    }
    auto ProbeCompletedTaskFailure(Net::any_io_executor Executor) -> Net::awaitable<TaskDrainProbe>
    {
        auto Failure = std::make_shared<Prism::Vless::Xudp::RunFailureState>();
        auto Registry = std::make_shared<Prism::Lifecycle::TaskRegistry>(
            std::move(Executor), Prism::Vless::Xudp::MakeRunFailureHandler(Failure));
        Prism::Lifecycle::TaskRequest Request{.Context = {}, .StartOnSubmit = true};
        const auto Submitted = Registry->SpawnTracked(std::move(Request), FailTrackedTask());
        const auto Drained = co_await Registry->Drain();
        const auto Stats = Registry->Stats();
        co_return TaskDrainProbe{static_cast<bool>(Submitted), static_cast<bool>(Drained),
            Prism::Vless::Xudp::TaskScopePhysicallyRetired(Stats), Failure->First, Stats};
    }
    auto Bytes(std::string_view Text) -> std::span<const std::byte>
    { return std::as_bytes(std::span(Text)); }
    auto NewFrame(std::uint16_t Id, std::uint16_t Port) -> std::vector<std::byte>
    {
        std::vector<std::byte> Wire{std::byte{0}, std::byte{12}, std::byte{0},
            std::byte{static_cast<std::uint8_t>(Id)}, std::byte{1}, std::byte{1}, std::byte{2},
            std::byte{static_cast<std::uint8_t>(Port >> 8)}, std::byte{static_cast<std::uint8_t>(Port)},
            std::byte{1}, std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1},
            std::byte{0}, std::byte{static_cast<std::uint8_t>(Payload.size())}};
        const auto Data = Bytes(Payload);
        Wire.insert(Wire.end(), Data.begin(), Data.end());
        return Wire;
    }
    auto Ipv6Frame(std::uint16_t Id, std::uint16_t Port) -> std::vector<std::byte>
    {
        std::vector<std::byte> Wire{std::byte{0}, std::byte{24},
            std::byte{static_cast<std::uint8_t>(Id >> 8)}, std::byte{static_cast<std::uint8_t>(Id)},
            std::byte{1}, std::byte{1}, std::byte{2},
            std::byte{static_cast<std::uint8_t>(Port >> 8)}, std::byte{static_cast<std::uint8_t>(Port)},
            std::byte{3}};
        Wire.insert(Wire.end(), 15, std::byte{0});
        Wire.push_back(std::byte{1});
        Wire.push_back(std::byte{0});
        Wire.push_back(std::byte{static_cast<std::uint8_t>(Payload.size())});
        const auto Data = Bytes(Payload);
        Wire.insert(Wire.end(), Data.begin(), Data.end());
        return Wire;
    }
    auto UnknownKeepFrame(std::uint16_t Id) -> std::array<std::byte, 6>
    {
        return {std::byte{0}, std::byte{4}, std::byte{static_cast<std::uint8_t>(Id >> 8)},
            std::byte{static_cast<std::uint8_t>(Id)}, std::byte{2}, std::byte{0}};
    }
    auto Write(Prism::SharedTransmission Stream, std::span<const std::byte> Wire) -> Net::awaitable<bool>
    {
        const auto Result = co_await Stream->WriteExact(Wire);
        co_return !Result.Failure.Failed() && Result.Bytes == Wire.size();
    }
    auto ReadExact(Prism::SharedTransmission Stream, std::span<std::byte> Buffer)
        -> Net::awaitable<bool>
    {
        const auto Result = co_await Stream->ReadExact(Buffer);
        co_return !Result.Failure.Failed() && Result.Bytes == Buffer.size();
    }
    auto ReadResponse(std::shared_ptr<Fixture> State, std::uint16_t Id) -> Net::awaitable<bool>
    {
        std::array<std::byte, 16> Header{};
        if (!(co_await ReadExact(State->Client, Header))) co_return false;
        const bool Valid = Header[0] == std::byte{0} && Header[1] == std::byte{12} &&
            Header[2] == std::byte{0} && Header[3] == std::byte{static_cast<std::uint8_t>(Id)} &&
            Header[4] == std::byte{2} && Header[5] == std::byte{1} && Header[6] == std::byte{2} &&
            Header[9] == std::byte{1} && Header[10] == std::byte{127} &&
            Header[11] == std::byte{0} && Header[12] == std::byte{0} && Header[13] == std::byte{1} &&
            Header[14] == std::byte{0} && Header[15] == std::byte{static_cast<std::uint8_t>(Payload.size())};
        std::array<std::byte, Payload.size()> Data{};
        if (!Valid || !(co_await ReadExact(State->Client, Data))) co_return false;
        co_return std::equal(Data.begin(), Data.end(), Bytes(Payload).begin());
    }
    auto ReadIpv6Response(std::shared_ptr<Fixture> State, std::uint16_t Id) -> Net::awaitable<bool>
    {
        std::array<std::byte, 28> Header{};
        if (!(co_await ReadExact(State->Client, Header))) co_return false;
        const bool Valid = Header[0] == std::byte{0} && Header[1] == std::byte{24} &&
            Header[2] == std::byte{0} && Header[3] == std::byte{static_cast<std::uint8_t>(Id)} &&
            Header[4] == std::byte{2} && Header[5] == std::byte{1} && Header[6] == std::byte{2} &&
            Header[9] == std::byte{3} && Header[10] == std::byte{0} && Header[24] == std::byte{0} &&
            Header[25] == std::byte{1} && Header[26] == std::byte{0} &&
            Header[27] == std::byte{static_cast<std::uint8_t>(Payload.size())};
        std::array<std::byte, Payload.size()> Data{};
        if (!Valid || !(co_await ReadExact(State->Client, Data))) co_return false;
        co_return std::equal(Data.begin(), Data.end(), Bytes(Payload).begin());
    }
    auto Resolve(std::shared_ptr<Fixture> S, Prism::Network::Target Target)
        -> Net::awaitable<std::expected<Udp::endpoint, Prism::Fault::Failure>>
    {
        const auto Address = Prism::Network::IpAddress(Target.Host);
        if (Address) co_return Udp::endpoint(*Address, Target.Port);
        ++S->ResolveCalls;
        struct Exit final
        {
            bool &Flag;
            ~Exit() { Flag = true; }
        } Guard{S->DnsExited};
        const auto Text = Prism::Network::ToText(Target.Host);
        auto Addresses = co_await S->Resolver->AsyncResolve(std::string(Text.View()));
        if (!Addresses) co_return std::unexpected(Addresses.error());
        if (Addresses->Empty())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::DnsFailed});
        }
        co_return Udp::endpoint((*Addresses)[0], Target.Port);
    }
    auto DomainFrame() ->std::vector<std::byte>
    {
        std::vector<std::byte> Frame{std::byte{0},std::byte{10},std::byte{0},std::byte{7},std::byte{1},std::byte{1},
            std::byte{2},std::byte{0},std::byte{53},std::byte{2},std::byte{1},std::byte{'x'},
            std::byte{0},std::byte{static_cast<std::uint8_t>(Payload.size())}};
        const auto Data=Bytes(Payload);Frame.insert(Frame.end(),Data.begin(),Data.end());return Frame;
    }
    auto RunRoot(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        Prism::Vless::ServerConfig Config;
        Config.AuthenticatorOwner = std::make_shared<Prism::DirectoryAuthenticator>(State->Directory->Credentials);
        Prism::Contract::DatagramServices Services;
        Services.IdleTimeout=State->Action==Lifecycle::DnsDeadline?std::chrono::milliseconds(50):
            ((State->Action==Lifecycle::DnsCancel||State->Action==Lifecycle::DnsEnd)?std::chrono::milliseconds(30000):std::chrono::milliseconds(200));
        Services.Traffic=std::make_shared<Traffic>(State);
        if(State->Action==Lifecycle::DnsDeadline||State->Action==Lifecycle::DnsCancel||State->Action==Lifecycle::DnsEnd)
        {
            const auto Weak=std::weak_ptr<Fixture>(State);
            Services.Resolve=[Weak](Prism::Network::Target Target)
                -> Net::awaitable<std::expected<Udp::endpoint, Prism::Fault::Failure>>
            {co_return co_await Resolve(Weak.lock(),std::move(Target));};
        }
        auto Factory = Prism::Testing::MakeVlessIngress(
            Config, Prism::Testing::ProtocolIngressResources{
                std::move(Services), State->GenerationUse, State->Server->Executor()},
            Prism::Vless::IngressRoute{});
        auto Input = MakeStreamAcceptInput(std::move(State->Server));
        auto Plane = co_await Factory->Accept(std::move(Input));
        State->Authenticated = Plane && Plane->ProtocolAuthenticated && bool(Plane->AccountLease);
        if (Plane)
        {
            State->Server = Plane->Transport();
            State->Owner = Plane->Mux()->Session;State->WeakOwner=State->Owner;
            Prism::Contract::MuxRootRequest Request;
            Request.Lease = std::move(Plane->AccountLease);
            Request.GenerationUseState = State->GenerationUse;
            const auto Run = co_await State->Owner->Run(std::move(Request));
            State->RunFailed = !Run;
            State->OwnerRetiredAfterRun = State->Owner->IsRetired();
        }
        Factory->Close();
        const auto FactoryDrain = co_await Factory->Drain();
        (void)FactoryDrain;
        State->FactoryRetiredAfterRun = Factory->IsRetired();
        State->GenerationUsesAfterRun = State->GenerationUse->Outstanding();
        State->Owner.reset();
        State->RootCompleted = true;
        State->Resolver.reset();
        if (State->Server)
        {
            State->Server->Close();
        }
    }
    auto RunEcho(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        std::array<std::byte, 256> Data{};
        Udp::endpoint From;
        boost::system::error_code Error;
        while (State->Echo.is_open())
        {
            const auto Count = co_await State->Echo.async_receive_from(Net::buffer(Data), From,
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
            State->EchoReceived += Count;
            (void)co_await State->Echo.async_send_to(Net::buffer(Data.data(), Count), From,
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
            if(State->MultipleReplies)
                (void)co_await State->Echo.async_send_to(Net::buffer(Data.data(),Count),From,Net::redirect_error(Net::use_awaitable,Error));
        }
    }
    auto RunEcho6(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        std::array<std::byte, 256> Data{};
        Udp::endpoint From;
        boost::system::error_code Error;
        while (State->Echo6.is_open())
        {
            const auto Count = co_await State->Echo6.async_receive_from(Net::buffer(Data), From,
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
            State->Echo6Received += Count;
            (void)co_await State->Echo6.async_send_to(Net::buffer(Data.data(), Count), From,
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
        }
    }
    auto ReadEnd(std::shared_ptr<Fixture> S,std::uint16_t Id)->Net::awaitable<bool>
    {
        std::array<std::byte,6> Wire{};
        const auto Received = co_await ReadExact(S->Client, Wire);
        co_return Received && Wire == std::array<std::byte,6>{std::byte{0},std::byte{4},std::byte{0},
            std::byte{static_cast<std::uint8_t>(Id)},std::byte{3},std::byte{2}};
    }
    auto DnsClient(std::shared_ptr<Fixture> S)->Net::awaitable<void>
    {
        EXPECT_TRUE(co_await Write(S->Client,DomainFrame()));
        std::array<std::byte,512> Query{};Udp::endpoint Peer;
        EXPECT_GT(co_await S->DnsSocket.async_receive_from(Net::buffer(Query),Peer,Net::use_awaitable),12U);
        S->DnsWasPending=!S->DnsExited&&S->ResolveCalls==1U;
        S->GenerationUsesDuringDns = S->GenerationUse->Outstanding();
        S->OwnerWasActiveDuringDns = S->Owner && !S->Owner->IsRetired();
        S->OwnerRetiredDuringDns = S->Owner && S->Owner->IsRetired();
        if(S->Action==Lifecycle::DnsCancel)S->Owner->Cancel();
        else
        {
            if(S->Action==Lifecycle::DnsEnd)
            {
                const std::array<std::byte,6> End{std::byte{0},std::byte{4},std::byte{0},std::byte{7},std::byte{3},std::byte{0}};
                EXPECT_TRUE(co_await Write(S->Client,End));
            }
            EXPECT_TRUE(co_await Write(S->Client,NewFrame(9,S->Echo.local_endpoint().port())));
            S->Second=co_await ReadResponse(S,9);
        }
        co_await S->Finished.async_receive(Net::use_awaitable);
        S->AfterDrainStreams=S->Record->Runtime()->ActiveStreams();
        EXPECT_TRUE(S->DnsExited);S->Close();
    }
    auto QuotaClient(std::shared_ptr<Fixture> S)->Net::awaitable<void>
    {
        EXPECT_TRUE(co_await Write(S->Client,NewFrame(7,S->Echo.local_endpoint().port())));
        S->First=co_await ReadResponse(S,7);S->StreamsAfterFirst=S->Record->Runtime()->ActiveStreams();
        EXPECT_TRUE(co_await Write(S->Client,NewFrame(9,S->Echo.local_endpoint().port())));
        S->Rejected=co_await ReadEnd(S,9);
        const std::array<std::byte,6> End{std::byte{0},std::byte{4},std::byte{0},std::byte{7},std::byte{3},std::byte{0}};
        EXPECT_TRUE(co_await Write(S->Client,End));co_await S->Finished.async_receive(Net::use_awaitable);
        S->AfterDrainStreams=S->Record->Runtime()->ActiveStreams();
        EXPECT_TRUE(co_await Write(S->Client,NewFrame(11,S->Echo.local_endpoint().port())));
        S->Second=co_await ReadResponse(S,11);S->Close();
    }
    auto RunClient(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        Prism::Vless::RequestHeader Header;
        Header.Uuid = State->Uuid;
        Header.Cmd = Prism::Vless::Command::Mux;
        Header.Target = {Prism::Vless::AddressType::Domain, "root.test", 443};
        const auto Request = Prism::Vless::BuildRequest(Header);
        EXPECT_TRUE(co_await Write(State->Client, std::as_bytes(std::span(Request))));
        std::array<std::byte, 2> Response{};
        const auto ResponseRead = co_await ReadExact(State->Client, Response);
        EXPECT_TRUE(ResponseRead);
        if (!ResponseRead) { State->Close(); co_return; }
        if(State->Action==Lifecycle::Quota){co_await QuotaClient(State);co_return;}
        if(State->Action==Lifecycle::FamilySwitch)
        {
            if (!State->Ipv6Ready)
            {
                State->Close();
                co_return;
            }
            EXPECT_TRUE(co_await Write(State->Client, NewFrame(7, State->Echo.local_endpoint().port())));
            State->First = co_await ReadResponse(State, 7);
            State->StreamsAfterFirst = State->Record->Runtime()->ActiveStreams();
            EXPECT_TRUE(co_await Write(State->Client, Ipv6Frame(7, State->Echo6.local_endpoint().port())));
            State->Second = co_await ReadIpv6Response(State, 7);
            const std::array<std::byte, 6> End{std::byte{0}, std::byte{4}, std::byte{0},
                std::byte{7}, std::byte{3}, std::byte{0}};
            EXPECT_TRUE(co_await Write(State->Client, End));
            co_await State->Finished.async_receive(Net::use_awaitable);
            State->AfterDrainStreams = State->Record->Runtime()->ActiveStreams();
            State->Close();
            co_return;
        }
        if(State->Action==Lifecycle::UnknownKeep)
        {
            const auto Keep = UnknownKeepFrame(99);
            EXPECT_TRUE(co_await Write(State->Client, Keep));
            State->UnknownKeepRejected = co_await ReadEnd(State, 99);
            State->StreamsAfterFirst = State->Record->Runtime()->ActiveStreams();
            EXPECT_TRUE(co_await Write(State->Client, NewFrame(7, State->Echo.local_endpoint().port())));
            State->First = co_await ReadResponse(State, 7);
            const std::array<std::byte, 6> End{std::byte{0}, std::byte{4}, std::byte{0},
                std::byte{7}, std::byte{3}, std::byte{0}};
            EXPECT_TRUE(co_await Write(State->Client, End));
            co_await State->Finished.async_receive(Net::use_awaitable);
            State->AfterDrainStreams = State->Record->Runtime()->ActiveStreams();
            State->Close();
            co_return;
        }
        if(State->Action!=Lifecycle::Ordinary){co_await DnsClient(State);co_return;}
        const auto Port = State->HeadOfLine ? State->Silent.local_endpoint().port() :
                                            State->Echo.local_endpoint().port();
        const auto First = NewFrame(7, Port);
        EXPECT_TRUE(co_await Write(State->Client, First));
        if (!State->HeadOfLine) State->First = co_await ReadResponse(State, 7);
        State->StreamsAfterFirst = State->Record->Runtime()->ActiveStreams();
        if(State->MultipleReplies){State->Second=co_await ReadResponse(State,7);State->Close();co_return;}
        const auto Second = NewFrame(9, State->Echo.local_endpoint().port());
        EXPECT_TRUE(co_await Write(State->Client, Second));
        State->Second = co_await ReadResponse(State, 9);
        if (!State->HeadOfLine && State->Second)
        {
            const std::array<std::byte, 6> End{std::byte{0}, std::byte{4}, std::byte{0},
                std::byte{7}, std::byte{3}, std::byte{0}};
            EXPECT_TRUE(co_await Write(State->Client, End));
            std::vector<std::byte> Keep{std::byte{0}, std::byte{4}, std::byte{0},
                std::byte{9}, std::byte{2}, std::byte{1}, std::byte{0},
                std::byte{static_cast<std::uint8_t>(Payload.size())}};
            Keep.insert(Keep.end(), Bytes(Payload).begin(), Bytes(Payload).end());
            (void)co_await Write(State->Client, Keep);
            State->SurvivedEnd = co_await ReadResponse(State, 9);
        }
        State->Close();
    }
    auto Watchdog(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        State->Deadline.expires_after(std::chrono::milliseconds(500));
        boost::system::error_code Error;
        co_await State->Deadline.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error) { State->TimedOut = true; State->Close(); }
    }
    auto Scenario(Options Configuration) -> Result
    {
        Net::io_context Io;
        auto State = std::make_shared<Fixture>(Io.get_executor(),Configuration.Action==Lifecycle::Quota,
            Configuration.Action==Lifecycle::FamilySwitch);
        State->HeadOfLine=Configuration.HeadOfLine;State->MultipleReplies=Configuration.MultipleReplies;State->Action=Configuration.Action;
        Prism::Network::Dns::Config DnsConfig;DnsConfig.DisableIpv6=true;DnsConfig.TimeoutMs=30000;DnsConfig.CacheEnabled=false;
        Prism::Network::Dns::Server Upstream;Upstream.Address="127.0.0.1";Upstream.Port=State->DnsSocket.local_endpoint().port();
        DnsConfig.Servers.push_back(Upstream);State->Resolver=std::make_shared<Prism::Network::Dns::Resolver>(Io.get_executor(),DnsConfig);
        const auto Complete = [State](std::exception_ptr Failure)
        { if (Failure) { State->Failure = Failure; State->Close(); } };
        Net::co_spawn(Io, RunRoot(State), Net::bind_cancellation_slot(State->RootCancel.slot(), Complete));
        Net::co_spawn(Io, RunEcho(State), Complete);
        Net::co_spawn(Io, RunEcho6(State), Complete);
        Net::co_spawn(Io, RunClient(State), Complete);
        Net::co_spawn(Io, Watchdog(State), Complete);
        Io.run();
        State->Close();
        return static_cast<const Result&>(*State);
    }
}
TEST(XudpSessionOwner, EndClosesOnlyNamedAssociationAndSiblingKeepsEchoing)
{
    const auto Actual = Scenario({});
    ASSERT_TRUE(Actual.Authenticated);
    ASSERT_TRUE(Actual.First);
    ASSERT_TRUE(Actual.Second);
    EXPECT_TRUE(Actual.SurvivedEnd);
    EXPECT_EQ(Actual.StreamsAfterFirst, 1);
    EXPECT_EQ(Actual.EchoReceived, Payload.size() * 3);
    EXPECT_TRUE(Actual.RootCompleted);
    EXPECT_FALSE(Actual.Failure);
    EXPECT_EQ(Actual.GenerationUsesDuringRun, 2U);
    EXPECT_TRUE(Actual.OwnerWasActiveDuringTraffic);
    EXPECT_EQ(Actual.GenerationUsesAfterRun, 0U);
    EXPECT_TRUE(Actual.OwnerRetiredAfterRun);
    EXPECT_TRUE(Actual.FactoryRetiredAfterRun);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(),0U);EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(),0U);
    EXPECT_TRUE(Actual.WeakOwner.expired());
}
TEST(XudpSessionOwner, SilentAssociationDoesNotDelaySiblingLiteralResponse)
{
    const auto Actual = Scenario({.HeadOfLine=true});
    ASSERT_TRUE(Actual.Authenticated);
    EXPECT_TRUE(Actual.Second);
    EXPECT_FALSE(Actual.TimedOut);
    EXPECT_EQ(Actual.EchoReceived, Payload.size());
    EXPECT_TRUE(Actual.RootCompleted);
    EXPECT_FALSE(Actual.Failure);
}

TEST(XudpSessionOwner, OneUpstreamDatagramCanProduceTwoIndependentLiteralReplies)
{
    const auto Actual=Scenario({.MultipleReplies=true});
    ASSERT_TRUE(Actual.Authenticated);ASSERT_TRUE(Actual.First);EXPECT_TRUE(Actual.Second);
    EXPECT_FALSE(Actual.TimedOut);EXPECT_EQ(Actual.EchoReceived,Payload.size());
    EXPECT_TRUE(Actual.RootCompleted);EXPECT_FALSE(Actual.Failure);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(),0U);EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(),0U);
    EXPECT_EQ(Actual.Reports,1U);EXPECT_EQ(Actual.Up,Payload.size());EXPECT_EQ(Actual.Down,Payload.size()*2);
    EXPECT_TRUE(Actual.WeakOwner.expired());
}

TEST(XudpSessionOwner, RealDnsDeadlineDrainsBackendWhileSiblingTransfers)
{
    const auto A=Scenario({.Action=Lifecycle::DnsDeadline});ASSERT_FALSE(A.Failure);ASSERT_TRUE(A.Authenticated);
    EXPECT_TRUE(A.DnsWasPending);EXPECT_TRUE(A.DnsExited);EXPECT_EQ(A.ResolveCalls,1U);EXPECT_TRUE(A.Second);
    EXPECT_FALSE(A.TimedOut);EXPECT_TRUE(A.RootCompleted);EXPECT_EQ(A.Reports,2U);EXPECT_EQ(A.Up,Payload.size());EXPECT_EQ(A.Down,Payload.size());
    EXPECT_EQ(A.Record->Runtime()->ActiveConnections(),0U);EXPECT_EQ(A.Record->Runtime()->ActiveStreams(),0U);EXPECT_TRUE(A.WeakOwner.expired());
}
TEST(XudpSessionOwner, RootCancelWaitsForRealDnsBackendToExit)
{
    const auto A=Scenario({.Action=Lifecycle::DnsCancel});ASSERT_FALSE(A.Failure);ASSERT_TRUE(A.Authenticated);
    EXPECT_TRUE(A.DnsWasPending);EXPECT_TRUE(A.DnsExited);EXPECT_EQ(A.ResolveCalls,1U);EXPECT_FALSE(A.TimedOut);
    EXPECT_FALSE(A.OwnerRetiredDuringDns);
    EXPECT_TRUE(A.RootCompleted);EXPECT_EQ(A.Reports,1U);EXPECT_EQ(A.Up,0U);EXPECT_EQ(A.Down,0U);
    EXPECT_TRUE(A.RunFailed);EXPECT_EQ(A.GenerationUsesDuringDns,2U);EXPECT_TRUE(A.OwnerWasActiveDuringDns);
    EXPECT_EQ(A.GenerationUsesAfterRun,0U);EXPECT_TRUE(A.OwnerRetiredAfterRun);
    EXPECT_TRUE(A.FactoryRetiredAfterRun);
    EXPECT_EQ(A.Record->Runtime()->ActiveConnections(),0U);EXPECT_EQ(A.Record->Runtime()->ActiveStreams(),0U);EXPECT_TRUE(A.WeakOwner.expired());
}
TEST(XudpSessionOwner, EndCancelsOnlyNamedRealDnsAndSiblingStillReplies)
{
    const auto A=Scenario({.Action=Lifecycle::DnsEnd});ASSERT_FALSE(A.Failure);ASSERT_TRUE(A.Authenticated);
    EXPECT_TRUE(A.DnsWasPending);EXPECT_TRUE(A.DnsExited);EXPECT_TRUE(A.Second);EXPECT_EQ(A.ResolveCalls,1U);EXPECT_FALSE(A.TimedOut);
    EXPECT_TRUE(A.RootCompleted);EXPECT_EQ(A.Reports,2U);EXPECT_EQ(A.Up,Payload.size());EXPECT_EQ(A.Down,Payload.size());
    EXPECT_EQ(A.Record->Runtime()->ActiveConnections(),0U);EXPECT_EQ(A.Record->Runtime()->ActiveStreams(),0U);EXPECT_TRUE(A.WeakOwner.expired());
}
TEST(XudpSessionOwner, RealQuotaRejectsAssociationWithoutSocketAndEndReturnsSlot)
{
    const auto A=Scenario({.Action=Lifecycle::Quota});ASSERT_FALSE(A.Failure);ASSERT_TRUE(A.Authenticated);ASSERT_TRUE(A.First);
    EXPECT_TRUE(A.Rejected);EXPECT_TRUE(A.Second);EXPECT_EQ(A.StreamsAfterFirst,1U);EXPECT_EQ(A.AfterDrainStreams,0U);
    EXPECT_EQ(A.EchoReceived,Payload.size()*2);EXPECT_EQ(A.Reports,2U);EXPECT_EQ(A.Up,Payload.size()*2);EXPECT_EQ(A.Down,Payload.size()*2);
    EXPECT_FALSE(A.TimedOut);EXPECT_TRUE(A.RootCompleted);EXPECT_EQ(A.Record->Runtime()->ActiveConnections(),0U);
    EXPECT_EQ(A.Record->Runtime()->ActiveStreams(),0U);EXPECT_TRUE(A.WeakOwner.expired());
}
TEST(XudpSessionOwner, SameAssociationSwitchesIpv4ToIpv6WithoutStaleReply)
{
    const auto A=Scenario({.Action=Lifecycle::FamilySwitch});
    ASSERT_FALSE(A.Failure);ASSERT_TRUE(A.Ipv6Ready);ASSERT_TRUE(A.Authenticated);
    EXPECT_TRUE(A.First);EXPECT_TRUE(A.Second);
    EXPECT_EQ(A.StreamsAfterFirst,1U);
    EXPECT_EQ(A.EchoReceived,Payload.size());EXPECT_EQ(A.Echo6Received,Payload.size());
    EXPECT_EQ(A.Reports,1U);EXPECT_EQ(A.Up,Payload.size()*2);EXPECT_EQ(A.Down,Payload.size()*2);
    EXPECT_EQ(A.AfterDrainStreams,0U);EXPECT_FALSE(A.TimedOut);EXPECT_TRUE(A.RootCompleted);
    EXPECT_EQ(A.Record->Runtime()->ActiveConnections(),0U);EXPECT_EQ(A.Record->Runtime()->ActiveStreams(),0U);
    EXPECT_TRUE(A.WeakOwner.expired());
}
TEST(XudpSessionOwner, UnknownKeepIsRejectedWithoutCreatingEgress)
{
    const auto A=Scenario({.Action=Lifecycle::UnknownKeep});
    ASSERT_FALSE(A.Failure);ASSERT_TRUE(A.Authenticated);EXPECT_TRUE(A.UnknownKeepRejected);EXPECT_TRUE(A.First);
    EXPECT_EQ(A.StreamsAfterFirst,0U);
    EXPECT_EQ(A.EchoReceived,Payload.size());EXPECT_EQ(A.Echo6Received,0U);
    EXPECT_EQ(A.Reports,1U);EXPECT_EQ(A.Up,Payload.size());EXPECT_EQ(A.Down,Payload.size());
    EXPECT_EQ(A.AfterDrainStreams,0U);EXPECT_TRUE(A.RootCompleted);EXPECT_FALSE(A.TimedOut);
    EXPECT_EQ(A.Record->Runtime()->ActiveConnections(),0U);EXPECT_EQ(A.Record->Runtime()->ActiveStreams(),0U);
    EXPECT_TRUE(A.WeakOwner.expired());
}

TEST(XudpSessionOwner, LiveDatagramKeepsRunGenerationLeaseUntilRetirement)
{
    const auto Actual = Scenario({});
    ASSERT_TRUE(Actual.Authenticated);
    ASSERT_TRUE(Actual.First);
    EXPECT_TRUE(Actual.OwnerWasActiveDuringTraffic);
    EXPECT_FALSE(Actual.OwnerRetiredDuringTraffic);
    EXPECT_EQ(Actual.GenerationUsesDuringRun, 2U);
    EXPECT_TRUE(Actual.RootCompleted);
    EXPECT_EQ(Actual.GenerationUsesAfterRun, 0U);
    EXPECT_TRUE(Actual.OwnerRetiredAfterRun);
    EXPECT_TRUE(Actual.FactoryRetiredAfterRun);
    EXPECT_TRUE(Actual.WeakOwner.expired());
}

TEST(XudpSessionOwner, CompletedTaskFailureDoesNotBlockPhysicalRetirementProof)
{
    Net::io_context Io;
    std::optional<TaskDrainProbe> Actual;
    std::exception_ptr Failure;
    Net::co_spawn(Io, ProbeCompletedTaskFailure(Io.get_executor()),
        [&Actual, &Failure](std::exception_ptr Error, TaskDrainProbe Value)
        {
            Failure = std::move(Error);
            Actual = std::move(Value);
        });
    Io.run();
    ASSERT_FALSE(Failure);
    ASSERT_TRUE(Actual);
    EXPECT_TRUE(Actual->Submitted);
    EXPECT_TRUE(Actual->DrainSucceeded);
    EXPECT_EQ(Actual->Stats.Failed, 1U);
    EXPECT_EQ(Actual->Stats.Active, 0U);
    EXPECT_FALSE(Actual->Stats.DrainBlocked);
    EXPECT_TRUE(Actual->PhysicallyRetired);
    EXPECT_TRUE(Actual->FirstFailure.Failed());
    EXPECT_EQ(Actual->FirstFailure.Native, std::make_error_code(std::errc::io_error));
}
