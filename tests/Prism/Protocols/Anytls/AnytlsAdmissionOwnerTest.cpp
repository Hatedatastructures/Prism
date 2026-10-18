/** @file AnytlsAdmissionOwnerTest.cpp @brief 实际账户 SYN 配额、FIN 兄弟隔离与根 drain。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/deferred.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <algorithm>
#include <expected>
#include <optional>
#include <stdexcept>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    constexpr std::string_view Literal{"A4-ACCOUNT-ECHO"};
    /**
     * @brief 用真实有界字节池构造 AnyTLS admission 接入输入。
     * @param Inbound fixture 移交的入站传输 owner。
     * @param Metadata fixture 持有的请求元数据快照。
     * @return 完整且唯一的接入输入。
     */
    [[nodiscard]] auto MakeStreamAcceptInput(Prism::SharedTransmission Inbound,
                               Prism::Contract::RequestMetadata Metadata)
        -> Prism::Contract::StreamAcceptInput
    {
        return {std::move(Inbound), std::move(Metadata),
            std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8})};
    }
    struct Result
    {
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState{
            std::make_shared<Prism::Foundation::GenerationUseState>()};
        bool Authenticated{false}, First{false}, Second{false}, Rejected{false}, AfterFin{false}, RootDone{false};
        bool RetiredAtRootReturn{false};
        std::expected<void, Prism::Fault::Failure> RootStatus;
        bool DialStarted{false}, DialCompleted{false}, DialCanceled{false};
        bool DialCompletionTimedOut{false};
        std::size_t Dials{0}, ActiveFirst{0}, ActiveAfterRejected{0}, Reports{0}, ByteReports{0},
            CompletedReports{0}, ObservationFailures{0}, CloseAttempts{0}, CloseFailures{0}, Up{0}, Down{0};
        std::size_t StoragePendingBeforeRetry{0}, StoragePendingAfterRetry{0}, RetryPasses{0};
        std::size_t ActiveStreamsBeforeRetry{0};
        std::size_t UsesWithNestedRoot{0}, UsesAtRootReturn{0};
        bool OutboundActivityFailureObserved{false}, OutboundRetainedBeforeRetry{false};
        std::exception_ptr Failure;
        std::weak_ptr<Prism::Contract::MuxSession> WeakRoot;
        std::weak_ptr<Prism::Transmission> WeakOutbound;
    };
    struct ScenarioOptions final
    {
        bool Siblings{false};
        bool Nested{false};
        bool ThrowTraffic{false};
        bool CloseTwice{false};
        bool CloseFailure{false};
    };
    struct Fixture final : Result
    {
        explicit Fixture(Net::any_io_executor Ex) : Acceptor(Ex, Tcp::endpoint(Tcp::v4(), 0)), Deadline(Ex), Finished(Ex, 8)
        {
            auto [C,S] = Prism::MakeMemoryPair(Ex);
            Client = std::make_shared<Prism::MemoryStream>(std::move(C));
            Server = std::make_shared<Prism::MemoryStream>(std::move(S));
            DialStartedSignal = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Ex, 1);
            DialRelease = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Ex, 1);
            DialCompletedSignal = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Ex, 1);
        }
        auto Stop() -> void
        {
            if (Owner) { Owner->Cancel(); Owner->Close(); }
            (void)Client->Close();
            if (Server) (void)Server->Close();
            boost::system::error_code Error;
            Acceptor.close(Error); Deadline.cancel();
            for (const auto& Socket : Targets) Socket->close(Error);
            DialStartedSignal->close(); DialRelease->close(); DialCompletedSignal->close();
        }
        Tcp::acceptor Acceptor;
        Net::steady_timer Deadline;
        Net::experimental::channel<void(boost::system::error_code)> Finished;
        Prism::SharedTransmission Client, Server;
        std::shared_ptr<Prism::Contract::MuxSession> Owner;
        std::vector<std::shared_ptr<Tcp::socket>> Targets;
        bool Siblings{false}, Nested{false}, HoldDial{false}, ThrowTraffic{false}, CloseTwice{false};
        bool CloseFailure{false};
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> DialStartedSignal;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> DialRelease;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> DialCompletedSignal;
    };
    class FailingTransmission final : public Prism::Transmission
    {
    public:
        FailingTransmission(Prism::SharedTransmission Inner, std::weak_ptr<Fixture> State)
            : Prism::Transmission(Inner->Executor()), Inner_(std::move(Inner)), State_(std::move(State)) {}
        auto Executor() const -> ExecutorType override { return Inner_->Executor(); }
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission* override
        { return Inner_.get(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission* override
        { return Inner_.get(); }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->ReadSome(Buffer, std::move(Handler));
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->WriteSome(Buffer, std::move(Handler));
        }
        /** @brief 测试替身显式兑现半关闭；原 Shutdown 沿实际 inner 转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        { Inner_->WriteShutdown(std::move(Handler)); }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            const auto InnerClose = Inner_->Close();
            if (!InnerClose) return std::unexpected(InnerClose.error());
            if (const auto State = State_.lock())
            {
                ++State->CloseAttempts;
                ++CloseCalls_;
                if (State->CloseFailure && CloseCalls_ == 1U)
                {
                    ++State->CloseFailures;
                    return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                }
            }
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override { (void)Inner_->Cancel(); return {}; }
        auto IsOpen() const -> bool override { return Inner_->IsOpen(); }
    private:
        Prism::SharedTransmission Inner_;
        std::weak_ptr<Fixture> State_;
        std::size_t CloseCalls_{0};
    };
    class Traffic final : public Prism::Foundation::TrafficSink
    {
    public:
        explicit Traffic(std::weak_ptr<Fixture> State) : State_(std::move(State)) {}
        auto Report(Prism::Foundation::TrafficEvent Event) noexcept -> void override
        {
            if (const auto State = State_.lock())
            {
                State->Up += Event.Up; State->Down += Event.Down;
                if (Event.Kind == Prism::Foundation::TrafficEventKind::Completed)
                {
                    ++State->Reports; ++State->CompletedReports;
                    (void)State->Finished.try_send(boost::system::error_code{});
                }
                else
                {
                    ++State->ByteReports;
                }
                try
                {
                    if (State->ThrowTraffic)
                        throw std::runtime_error("AnyTLS observer failure");
                }
                catch (...)
                {
                    ++State->ObservationFailures;
                }
            }
        }
        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }
    private:
        std::weak_ptr<Fixture> State_;
    };
    class Egress final : public Prism::Contract::StreamEgress
    {
    public:
        explicit Egress(std::weak_ptr<Fixture> State) : State_(std::move(State)) {}
        auto Connect(Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>> override
        {
            const auto State = State_.lock();
            if (State)
            {
                ++State->Dials;
                if (State->HoldDial)
                {
                    State->DialStarted = true;
                    (void)State->DialStartedSignal->try_send(boost::system::error_code{});
                    boost::system::error_code GateError;
                    co_await State->DialRelease->async_receive(
                        Net::redirect_error(Net::use_awaitable, GateError));
                    State->DialCompleted = true;
                    State->DialCanceled = bool(GateError);
                    (void)State->DialCompletedSignal->try_send(boost::system::error_code{});
                    co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                }
            }
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code Error;
            co_await Socket.async_connect(Tcp::endpoint(*Prism::Network::IpAddress(Target.Host),
                Target.Port), Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::Unreachable, static_cast<std::error_code>(Error)});
            }
            auto Reliable = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
            if (State && State->CloseFailure)
            {
                auto Outbound = std::make_shared<FailingTransmission>(Reliable, State);
                State->WeakOutbound = Outbound;
                co_return Prism::SharedTransmission{std::move(Outbound)};
            }
            co_return Prism::SharedTransmission{std::move(Reliable)};
        }
    private:
        std::weak_ptr<Fixture> State_;
    };
    auto Echo(std::shared_ptr<Tcp::socket> Socket) -> Net::awaitable<void>
    {
        std::array<std::byte, 256> Buffer{};
        boost::system::error_code Error;
        for (;;)
        {
            const auto Count = co_await Socket->async_read_some(Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count == 0) break;
            (void)co_await Net::async_write(*Socket, Net::buffer(Buffer.data(), Count), Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
        }
        Socket->close(Error);
    }
    auto Accept(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        const auto Ex = co_await Net::this_coro::executor;
        while (State->Acceptor.is_open())
        {
            auto Socket = std::make_shared<Tcp::socket>(Ex);
            boost::system::error_code Error;
            co_await State->Acceptor.async_accept(*Socket, Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
            State->Targets.push_back(Socket);
            Net::co_spawn(Ex, Echo(Socket), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
        }
    }
    auto Frame(std::uint8_t Kind, std::uint32_t Id, std::span<const std::byte> Payload = {}) -> std::vector<std::byte>
    {
        std::vector<std::byte> Wire{std::byte{Kind},std::byte{static_cast<std::uint8_t>(Id >> 24)},
            std::byte{static_cast<std::uint8_t>(Id >> 16)},std::byte{static_cast<std::uint8_t>(Id >> 8)},
            std::byte{static_cast<std::uint8_t>(Id)},std::byte{static_cast<std::uint8_t>(Payload.size() >> 8)},
            std::byte{static_cast<std::uint8_t>(Payload.size())}};
        Wire.insert(Wire.end(), Payload.begin(), Payload.end()); return Wire;
    }
    auto Write(std::shared_ptr<Fixture> State, std::vector<std::byte> Wire) -> Net::awaitable<void>
    {
        std::error_code Error;
        const auto Written = co_await State->Client->WriteExact(Wire);
        Error = Prism::Fault::ToNative(Written.Failure);
        EXPECT_FALSE(Error);
    }
    auto WriteChecked(std::shared_ptr<Fixture> State, std::vector<std::byte> Wire)
        -> Net::awaitable<bool>
    {
        std::error_code Error;
        const auto Written = co_await State->Client->WriteExact(Wire);
        Error = Prism::Fault::ToNative(Written.Failure);
        const auto Count = Written.Bytes;
        co_return !Error && Count == Wire.size();
    }
    auto Read(std::shared_ptr<Fixture> State) -> Net::awaitable<Prism::Anytls::Frame>
    {
        auto Value = co_await Prism::Anytls::ReadFrame(State->Client);
        EXPECT_TRUE(Value); co_return Value ? std::move(*Value) : Prism::Anytls::Frame{};
    }
    auto Push(std::shared_ptr<Fixture> State, std::uint32_t Id) -> Net::awaitable<void>
    {
        const auto Port = State->Acceptor.local_endpoint().port();
        std::vector<std::byte> Bytes{std::byte{1},std::byte{127},std::byte{0},std::byte{0},std::byte{1},
            std::byte{static_cast<std::uint8_t>(Port >> 8)},std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Data = std::as_bytes(std::span(Literal)); Bytes.insert(Bytes.end(), Data.begin(), Data.end());
        co_await Write(State, Frame(1, Id)); co_await Write(State, Frame(2, Id, Bytes));
    }
    auto EchoResponse(std::shared_ptr<Fixture> State, std::uint32_t Id) -> Net::awaitable<bool>
    {
        for (int Index=0;Index<3;++Index)
        {
            const auto Value = co_await Read(State);
            if (Value.StreamId == Id && Value.Kind == Prism::Anytls::Command::Push)
                co_return Value.Payload.size() == Literal.size() &&
                    std::equal(Value.Payload.begin(), Value.Payload.end(), std::as_bytes(std::span(Literal)).begin());
        }
        co_return false;
    }
    auto Root(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("task4-account-password"),
            Prism::AccountId{4500},
            {.MaxConnections=1,.MaxStreams=(State->Siblings||State->Nested)?2U:1U});
        State->Record = Directory->Store->FindById(Prism::AccountId{4500});
        EXPECT_TRUE(State->Record);
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8U});
        Prism::Anytls::IngressFactory Factory({.Configuration={"task4-account-password"},
            .Streams={.Egress=std::make_shared<Egress>(State),.Traffic=std::make_shared<Traffic>(State),
                .Bytes=std::move(Bytes)},
            .Authenticator=Directory->Authenticator});
        auto Input = MakeStreamAcceptInput(std::move(State->Server), {});
        Input.GenerationUseState = State->UseState;
        auto Plane = co_await Factory.Accept(std::move(Input));
        State->Authenticated = Plane && bool(Plane->AccountLease);
        if (!Plane) co_return;
        State->Server = Plane->Transport();
        State->Owner=Plane->Mux()->Session; State->WeakRoot=State->Owner;
        Prism::Contract::MuxRootRequest Request; Request.Lease=std::move(Plane->AccountLease);
        Request.GenerationUseState = State->UseState;
        State->RootStatus = co_await State->Owner->Run(std::move(Request));
        State->UsesAtRootReturn = State->UseState->Outstanding();
        State->RetiredAtRootReturn = State->Owner->IsRetired();
        if (State->CloseFailure) EXPECT_FALSE(State->RetiredAtRootReturn);
        else EXPECT_TRUE(State->RetiredAtRootReturn);
        State->RootDone=true;
        if (State->CloseFailure)
            if (const auto Outbound = State->WeakOutbound.lock())
            {
                const auto Drained = co_await Outbound->Activity()->Drain();
                State->OutboundActivityFailureObserved = !Drained &&
                    Drained.error().Code == Prism::Fault::Code::IoError;
            }
        if (State->CloseTwice && State->Owner)
        {
            State->Owner->Close(); State->Owner->Close();
        }
        State->Owner.reset(); State->Stop();
    }
    class NestedTransport final : public Prism::Transmission
    {
    public:
        explicit NestedTransport(std::shared_ptr<Fixture> State)
            : Prism::Transmission(State->Client->Executor()), State_(std::move(State)) {}
        auto Executor() const -> ExecutorType override { return State_->Client->Executor(); }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Completion Routed(Prism::Transport::Detail::OriginalCompletion(
                Executor(), std::move(Handler)));
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{}, Executor()), Routed,
                ReadInput{std::static_pointer_cast<NestedTransport>(Prism::Transmission::shared_from_this()), Buffer});
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Completion Routed(Prism::Transport::Detail::OriginalCompletion(
                Executor(), std::move(Handler)));
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(WriteWork{}, Executor()), Routed,
                WriteInput{std::static_pointer_cast<NestedTransport>(Prism::Transmission::shared_from_this()), Buffer});
        }
        /** @brief 原空体 Shutdown 立即成功；新前门显式投递同一结果。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        { Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), {}); }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            if (!ReadFailure_) ReadFailure_ = Prism::Fault::Failure{Prism::Fault::Code::Eof};
            (void)State_->Client->Close();
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            Closed_ = true;
            if (!ReadFailure_) ReadFailure_ = Prism::Fault::Failure{Prism::Fault::Code::Canceled};
            (void)State_->Client->Cancel();
            return {};
        }
        auto IsOpen() const -> bool override {return !Closed_&&State_->Client->IsOpen();}
    private:
        struct ReadInput final
        {
            std::shared_ptr<NestedTransport> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<NestedTransport> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                auto [Exception, Result] = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer),
                    Net::as_tuple(Net::deferred));
                if (Exception)
                {
                    co_return std::tuple{Prism::IoResult{0,
                        Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Exception))}};
                }
                co_return std::tuple{std::move(Result)};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                auto [Exception, Result] = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer),
                    Net::as_tuple(Net::deferred));
                if (Exception)
                {
                    co_return std::tuple{Prism::IoResult{0,
                        Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Exception))}};
                }
                co_return std::tuple{std::move(Result)};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (Buffer.empty()) co_return Prism::IoResult{};
            while (Pending_.empty() && !Closed_)
            {
                auto Packet = co_await Prism::Anytls::ReadFrame(State_->Client);
                if (!Packet)
                {
                    Closed_ = true;
                    ReadFailure_ = Prism::Fault::FromNative(
                        Prism::make_error_code(Packet.error()));
                    break;
                }
                if (Packet->StreamId != 1) continue;
                if (Packet->Kind == Prism::Anytls::Command::Push)
                {
                    Pending_ = std::move(Packet->Payload);
                }
                else if (Packet->Kind == Prism::Anytls::Command::Fin)
                {
                    Closed_ = true;
                    ReadFailure_ = Prism::Fault::Failure{Prism::Fault::Code::Eof};
                }
            }
            const auto Count = (std::min)(Buffer.size(), Pending_.size());
            std::copy_n(Pending_.begin(), Count, Buffer.begin());
            Pending_.erase(Pending_.begin(),
                Pending_.begin() + static_cast<std::ptrdiff_t>(Count));
            if (Count != 0U) co_return Prism::IoResult{Count, {}};
            if (ReadFailure_) co_return Prism::IoResult{0U, *ReadFailure_};
            co_return Prism::IoResult{0U, {Prism::Fault::Code::WouldBlock}};
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            const auto Wire=Frame(2,1,Buffer);
            const auto Write=co_await State_->Client->WriteExact(Wire);
            if (Write.Failure.Failed()) co_return Prism::IoResult{Write.Bytes, Write.Failure};
            if (Write.Bytes != Wire.size())
                co_return Prism::IoResult{Write.Bytes, {Prism::Fault::Code::IoError}};
            co_return Prism::IoResult{Buffer.size(), {}};
        }
        std::shared_ptr<Fixture> State_;
        std::vector<std::byte> Pending_;
        std::optional<Prism::Fault::Failure> ReadFailure_;
        bool Closed_{false};
    };
    auto NestedClient(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        constexpr std::string_view Domain{"sp.mux.sing-box.arpa"};
        std::vector<std::byte> Target{std::byte{3},std::byte{static_cast<std::uint8_t>(Domain.size())}};
        const auto Name=std::as_bytes(std::span(Domain));Target.insert(Target.end(),Name.begin(),Name.end());
        Target.insert(Target.end(),{std::byte{0},std::byte{80},std::byte{0},std::byte{0}});
        co_await Write(State,Frame(1,1));co_await Write(State,Frame(2,1,Target));
        const auto Ack=co_await Read(State);EXPECT_EQ(Ack.Kind,Prism::Anytls::Command::SynAck);EXPECT_TRUE(Ack.Payload.empty());
        auto Client=std::make_shared<Prism::Mux::Smux::Client<>>();
        EXPECT_TRUE(Client->Connect(std::make_shared<NestedTransport>(State)));
        auto Stream=co_await Client->OpenStream();EXPECT_TRUE(Stream);if(!Stream)co_return;
        const auto Port=State->Acceptor.local_endpoint().port();
        std::vector<std::byte> Request{std::byte{0},std::byte{0},std::byte{1},std::byte{127},std::byte{0},std::byte{0},std::byte{1},
            std::byte{static_cast<std::uint8_t>(Port>>8)},std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Bytes=std::as_bytes(std::span(Literal));Request.insert(Request.end(),Bytes.begin(),Bytes.end());
        std::error_code Error;
        const auto Written=co_await Stream->WriteExact(Request);
        Error=Prism::Fault::ToNative(Written.Failure);EXPECT_FALSE(Error);
        std::array<std::byte,Literal.size()+1> Reply{};
        const auto ReadResult=co_await Stream->ReadExact(Reply);
        Error=Prism::Fault::ToNative(ReadResult.Failure);EXPECT_FALSE(Error);
        State->First=!Error&&Reply[0]==std::byte{0}&&std::equal(Reply.begin()+1,Reply.end(),Bytes.begin());
        State->UsesWithNestedRoot = State->UseState->Outstanding();
        State->ActiveFirst=State->Record->Runtime()->ActiveStreams();(void)Stream->Close();
        co_await State->Finished.async_receive(Net::use_awaitable);State->ActiveAfterRejected=State->Record->Runtime()->ActiveStreams();
        co_await Client->Session()->Close();(void)State->Client->Close();
    }
    auto Client(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        std::string Auth; (void)Prism::Anytls::BuildAuthFrame("task4-account-password",0,Auth);
        co_await Write(State, std::vector<std::byte>(reinterpret_cast<const std::byte*>(Auth.data()),
            reinterpret_cast<const std::byte*>(Auth.data())+Auth.size()));
        constexpr std::string_view Settings{"v=2\nclient=task4\n"};
        co_await Write(State, Frame(4,0,std::as_bytes(std::span(Settings)))); (void)co_await Read(State);
        if(State->Nested){co_await NestedClient(State);co_return;}
        co_await Push(State,1); State->First=co_await EchoResponse(State,1);
        State->ActiveFirst=State->Record->Runtime()->ActiveStreams();
        co_await Push(State,3);
        if (State->Siblings) State->Second=co_await EchoResponse(State,3);
        else
        {
            const auto Reply=co_await Read(State);
            State->Rejected=Reply.StreamId==3 && Reply.Kind==Prism::Anytls::Command::SynAck && !Reply.Payload.empty();
            State->ActiveAfterRejected=State->Record->Runtime()->ActiveStreams();
        }
        co_await Write(State, Frame(3,1));
        if (State->CloseFailure)
        {
            (void)State->Client->Close();
            co_return;
        }
        co_await State->Finished.async_receive(Net::use_awaitable);
        if (State->Siblings)
        {
            co_await Write(State,Frame(2,3,std::as_bytes(std::span(Literal))));
            State->AfterFin=co_await EchoResponse(State,3);
        }
        else { co_await Push(State,5); State->AfterFin=co_await EchoResponse(State,5); }
        (void)State->Client->Close();
    }
    auto Watchdog(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        State->Deadline.expires_after(std::chrono::seconds(3)); boost::system::error_code Error;
        co_await State->Deadline.async_wait(Net::redirect_error(Net::use_awaitable,Error));
        if(!Error){ADD_FAILURE()<<"AnyTLS账户路径未实际drain";State->Stop();}
    }
    auto Scenario(ScenarioOptions Options = {}) -> Result
    {
        Net::io_context Io;
        auto Storage = Options.CloseFailure ? std::make_shared<Prism::Executor::ClosingStorage>() : nullptr;
        auto Context = Options.CloseFailure ? Prism::Executor::ContextOwner::Create(Storage) : nullptr;
        auto &DrivenIo = Context ? Context->Io : Io;
        auto State=std::make_shared<Fixture>(DrivenIo.get_executor());State->Siblings=Options.Siblings;State->Nested=Options.Nested;State->ThrowTraffic=Options.ThrowTraffic;State->CloseTwice=Options.CloseTwice;State->CloseFailure=Options.CloseFailure;
        const auto Done=[State](std::exception_ptr Error){if(Error){State->Failure=Error;State->Stop();}};
        Net::co_spawn(DrivenIo,Root(State),Done);Net::co_spawn(DrivenIo,Accept(State),Done);
        Net::co_spawn(DrivenIo,Client(State),Done);Net::co_spawn(DrivenIo,Watchdog(State),Done);
        DrivenIo.run();
        if (Storage)
        {
            State->StoragePendingBeforeRetry = Storage->Pending();
            State->OutboundRetainedBeforeRetry = !State->WeakOutbound.expired();
            State->ActiveStreamsBeforeRetry = State->Record->Runtime()->ActiveStreams();
            for (std::size_t Attempt = 0; Attempt < 4 && Storage->Pending() != 0; ++Attempt)
            {
                ++State->RetryPasses;
                Storage->Retry();
                DrivenIo.restart();
                DrivenIo.run();
            }
            State->StoragePendingAfterRetry = Storage->Pending();
        }
        State->Owner.reset();return static_cast<const Result&>(*State);
    }

    auto PendingDialClient(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        std::string Auth; (void)Prism::Anytls::BuildAuthFrame("task4-account-password",0,Auth);
        if (!co_await WriteChecked(State, std::vector<std::byte>(reinterpret_cast<const std::byte*>(Auth.data()),
            reinterpret_cast<const std::byte*>(Auth.data())+Auth.size()))) co_return;
        constexpr std::string_view Settings{"v=2\nclient=pending-dial\n"};
        if (!co_await WriteChecked(State, Frame(4,0,std::as_bytes(std::span(Settings))))) co_return;
        const auto Reply=co_await Read(State);
        if (Reply.Kind!=Prism::Anytls::Command::ServerSettings) co_return;
        const auto Port = State->Acceptor.local_endpoint().port();
        std::vector<std::byte> Bytes{std::byte{1},std::byte{127},std::byte{0},std::byte{0},std::byte{1},
            std::byte{static_cast<std::uint8_t>(Port >> 8)},std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Data=std::as_bytes(std::span(Literal)); Bytes.insert(Bytes.end(),Data.begin(),Data.end());
        if (!co_await WriteChecked(State, Frame(1,1)) ||
            !co_await WriteChecked(State, Frame(2,1,Bytes))) co_return;
        std::array<std::byte,7> Buffer{}; std::error_code Error;
        const auto Read=co_await State->Client->ReadSome(Buffer);
        Error=Prism::Fault::ToNative(Read.Failure);
    }

    auto CancelPendingDial(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        co_await State->DialStartedSignal->async_receive(Net::use_awaitable);
        if (State->Owner)
        {
            State->Owner->Cancel(); State->Owner->Close();
        }
        co_await State->DialCompletedSignal->async_receive(Net::use_awaitable);
        State->Deadline.cancel();
        State->DialRelease->close();
        (void)State->Client->Close();
    }

    auto DialCancellationWatchdog(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        State->Deadline.expires_after(std::chrono::seconds(3));
        boost::system::error_code Error;
        co_await State->Deadline.async_wait(Net::redirect_error(Net::use_awaitable,Error));
        if (!Error && !State->DialCompleted)
        {
            State->DialCompletionTimedOut=true;
            State->Stop();
            State->DialRelease->close();
        }
    }

    auto PendingDialScenario() -> Result
    {
        Net::io_context Io;
        auto State=std::make_shared<Fixture>(Io.get_executor());
        State->HoldDial=true;
        const auto Done=[State](std::exception_ptr Error){if(Error){State->Failure=Error;State->Stop();}};
        Net::co_spawn(Io,Root(State),Done);
        Net::co_spawn(Io,PendingDialClient(State),Done);
        Net::co_spawn(Io,CancelPendingDial(State),Done);
        Net::co_spawn(Io,DialCancellationWatchdog(State),Done);
        Io.run();
        const auto Actual=static_cast<const Result&>(*State);
        State->Stop();
        return Actual;
    }

}
TEST(AnytlsAdmissionOwner, RealQuotaRejectsSecondAndFinReturnsSlotBeforeReplacement)
{
    const auto Actual=Scenario({.Siblings=false});
    ASSERT_FALSE(Actual.Failure);ASSERT_TRUE(Actual.Authenticated);ASSERT_TRUE(Actual.First);
    EXPECT_TRUE(Actual.Rejected);EXPECT_EQ(Actual.ActiveFirst,1);EXPECT_EQ(Actual.ActiveAfterRejected,1);
    EXPECT_TRUE(Actual.AfterFin);EXPECT_EQ(Actual.Dials,2);EXPECT_TRUE(Actual.RootDone);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(),0);EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(),0);
    EXPECT_EQ(Actual.Reports,2);EXPECT_EQ(Actual.Up,Literal.size()*2);EXPECT_EQ(Actual.Down,Literal.size()*2);
    EXPECT_TRUE(Actual.WeakRoot.expired());
}
TEST(AnytlsAdmissionOwner, PeerFinTerminatesOnlyNamedChildAndSiblingKeepsLiteralEcho)
{
    const auto Actual=Scenario({.Siblings=true});
    ASSERT_FALSE(Actual.Failure);ASSERT_TRUE(Actual.Authenticated);ASSERT_TRUE(Actual.First);ASSERT_TRUE(Actual.Second);
    EXPECT_TRUE(Actual.AfterFin);EXPECT_EQ(Actual.Dials,2);EXPECT_TRUE(Actual.RootDone);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(),0);EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(),0);
    EXPECT_EQ(Actual.Reports,2);EXPECT_EQ(Actual.Up,Literal.size()*3);EXPECT_EQ(Actual.Down,Literal.size()*3);
    EXPECT_TRUE(Actual.WeakRoot.expired());
}

TEST(AnytlsAdmissionOwner, NestedSingMuxDrainsItsOwnBranchAndCountsPayloadOnlyOnce)
{
    const auto Actual=Scenario({.Siblings=false,.Nested=true});
    ASSERT_FALSE(Actual.Failure);ASSERT_TRUE(Actual.Authenticated);ASSERT_TRUE(Actual.First);
    EXPECT_EQ(Actual.ActiveFirst,2U);EXPECT_EQ(Actual.ActiveAfterRejected,1U);EXPECT_EQ(Actual.Dials,1U);
    EXPECT_TRUE(Actual.RootDone);EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(),0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(),0U);EXPECT_EQ(Actual.Reports,2U);
    EXPECT_EQ(Actual.Up,Literal.size());EXPECT_EQ(Actual.Down,Literal.size());EXPECT_TRUE(Actual.WeakRoot.expired());
    EXPECT_EQ(Actual.UsesWithNestedRoot,2U);EXPECT_EQ(Actual.UsesAtRootReturn,0U);
}

TEST(AnytlsAdmissionOwner, PendingDialCancellationCompletesWithoutLeakingRoot)
{
    const auto Actual=PendingDialScenario();
    ASSERT_FALSE(Actual.Failure);
    ASSERT_TRUE(Actual.Authenticated);
    EXPECT_TRUE(Actual.DialStarted);
    EXPECT_TRUE(Actual.DialCompleted);
    EXPECT_TRUE(Actual.DialCanceled);
    EXPECT_FALSE(Actual.DialCompletionTimedOut);
    EXPECT_TRUE(Actual.RootDone);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(),0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(),0U);
    // 已准入 stream 即使取消前没有 payload，也要在 completion 时报告一次零字节结果。
    EXPECT_EQ(Actual.Reports,1U);
    EXPECT_EQ(Actual.Up,0U);
    EXPECT_EQ(Actual.Down,0U);
    EXPECT_TRUE(Actual.WeakRoot.expired());
}

TEST(AnytlsAdmissionOwner, ObserverThrowPreservesPayloadAndBusinessCompletion)
{
    const auto Actual=Scenario({.ThrowTraffic=true});
    ASSERT_FALSE(Actual.Failure);
    ASSERT_TRUE(Actual.Authenticated);
    ASSERT_TRUE(Actual.First);
    EXPECT_TRUE(Actual.AfterFin);
    EXPECT_TRUE(Actual.RootDone);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(),0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(),0U);
    EXPECT_EQ(Actual.Reports,2U);
    EXPECT_EQ(Actual.CompletedReports, Actual.Reports);
    EXPECT_GT(Actual.ByteReports, 0U);
    EXPECT_EQ(Actual.ObservationFailures, Actual.ByteReports + Actual.CompletedReports);
    EXPECT_EQ(Actual.Up,Literal.size()*2);
    EXPECT_EQ(Actual.Down,Literal.size()*2);
    EXPECT_TRUE(Actual.WeakRoot.expired());
}

TEST(AnytlsAdmissionOwner, RealOutboundCloseFailureDrainsAndReportsTypedFailure)
{
    const auto Actual=Scenario({.CloseFailure=true});
    ASSERT_FALSE(Actual.Failure);
    ASSERT_TRUE(Actual.Authenticated);
    ASSERT_TRUE(Actual.First);
    EXPECT_TRUE(Actual.RootDone);
    ASSERT_FALSE(Actual.RootStatus);
    EXPECT_EQ(Actual.RootStatus.error().Code, Prism::Fault::Code::IoError);
    EXPECT_GE(Actual.CloseAttempts, 1U);
    EXPECT_GT(Actual.CloseFailures, 0U);
    EXPECT_EQ(Actual.Reports, 2U);
    EXPECT_EQ(Actual.CompletedReports, Actual.Reports);
    EXPECT_GT(Actual.ByteReports, 0U);
    EXPECT_EQ(Actual.Up, Literal.size() * 2);
    EXPECT_EQ(Actual.Down, Literal.size() * 2);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Actual.UsesAtRootReturn, 0U);
    EXPECT_FALSE(Actual.RetiredAtRootReturn);
    EXPECT_EQ(Actual.ActiveStreamsBeforeRetry, 1U);
    EXPECT_TRUE(Actual.OutboundActivityFailureObserved);
    EXPECT_GT(Actual.StoragePendingBeforeRetry, 0U);
    EXPECT_TRUE(Actual.OutboundRetainedBeforeRetry);
    EXPECT_GT(Actual.RetryPasses, 0U);
    EXPECT_EQ(Actual.StoragePendingAfterRetry, 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(), 0U);
    EXPECT_TRUE(Actual.WeakOutbound.expired());
    EXPECT_TRUE(Actual.WeakRoot.expired());
}

TEST(AnytlsAdmissionOwner, RepeatedRootCloseKeepsSingleReportsAndReleasesLease)
{
    const auto Actual=Scenario({.Siblings=true,.CloseTwice=true});
    ASSERT_FALSE(Actual.Failure);
    ASSERT_TRUE(Actual.Authenticated);
    ASSERT_TRUE(Actual.First);
    ASSERT_TRUE(Actual.Second);
    EXPECT_TRUE(Actual.AfterFin);
    EXPECT_TRUE(Actual.RootDone);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(),0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(),0U);
    EXPECT_EQ(Actual.Reports,2U);
    EXPECT_EQ(Actual.Up,Literal.size()*3);
    EXPECT_EQ(Actual.Down,Literal.size()*3);
    EXPECT_TRUE(Actual.WeakRoot.expired());
}
