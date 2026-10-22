/** @file MuxH2RootOwnerTest.cpp @brief 实际 Trojan 认证、标准 HTTP2 child 与 root completion。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Runtime/SessionRegistry.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2Server.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <atomic>
#include <map>
#include <optional>
#include <system_error>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    constexpr std::string_view Payload{"A4-H2-REAL-PAYLOAD"};
    [[nodiscard]] auto MakeStreamAcceptInput(Prism::SharedTransmission Inbound)
        -> Prism::Contract::StreamAcceptInput
    {
        return {std::move(Inbound), {}, std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8})};
    }
    struct Result
    {
        bool Authenticated{false}, Echo{false}, RootFinished{false}, ReadFinishedAtRootReturn{false};
        bool FirstEcho{false}, SecondRejected{false}, ReplacementEcho{false};
        bool StreamResetCompleted{false}, SiblingSurvived{false}, FirstResetObserved{false};
        std::uint32_t FirstResetCode{0};
        Prism::Http2::StreamReceiveClosureKind FirstClosureKind{
            Prism::Http2::StreamReceiveClosureKind::EndStream};
        std::size_t TargetBytes{0}, TargetConnections{0}, ReportsAtRootReturn{0};
        std::size_t Dials{0}, DialsAfterSecond{0}, FirstStreams{0};
        std::exception_ptr Failure;
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState{
            std::make_shared<Prism::Foundation::GenerationUseState>()};
        std::size_t UsesWithSibling{0}, UsesAtRootReturn{0};
        std::weak_ptr<Prism::Contract::MuxSession> WeakRoot;
        std::weak_ptr<Prism::Transmission> WeakOutbound;
    };
    struct Fixture final : Result
    {
        explicit Fixture(
            Net::any_io_executor Ex,
            const std::size_t MaxStreamsValue = 4U,
            const std::size_t ExpectedConnectionsValue = 0U)
            : Acceptor(Ex, Tcp::endpoint(Tcp::v4(), 0)), Target(Ex), Deadline(Ex), ChildDone(Ex, 8),
              ExpectedConnections(ExpectedConnectionsValue != 0U ? ExpectedConnectionsValue :
                  (MaxStreamsValue == 1U ? 2U : 1U))
        {
            auto [C, S] = Prism::MakeMemoryPair(Ex);
            Client = std::make_shared<Prism::MemoryStream>(std::move(C));
            Server = std::make_shared<Prism::MemoryStream>(std::move(S));
            auto MutableDirectory = Prism::Testing::ProviderAccount(
                Prism::Account::Credential::Token(Prism::Trojan::Credential("task4-h2")),
                Prism::AccountId{4402}, {.MaxConnections = 1, .MaxStreams = MaxStreamsValue});
            Record = MutableDirectory->Store->FindById(Prism::AccountId{4402});
            EXPECT_TRUE(Record);
            Directory = std::move(MutableDirectory);
            Catalog = std::make_shared<Prism::Contract::Ingress::StreamCatalog>();
        }
        auto Stop() -> void
        {
            const auto ClientClose = Client->Close();
            const auto ServerClose = Server ? Server->Close() : Prism::Transmission::ControlResult{};
            if (!ClientClose || !ServerClose) Failure = std::make_exception_ptr(std::runtime_error("fixture close failed"));
            if (Owner) { Owner->Cancel(); Owner->Close(); }
            boost::system::error_code Error;
            Acceptor.close(Error); Target.close(Error); Deadline.cancel();
        }
        Tcp::acceptor Acceptor;
        Tcp::socket Target;
        Net::steady_timer Deadline;
        Prism::SharedTransmission Client, Server;
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Prism::Contract::Ingress::StreamCatalog> Catalog;
        Prism::Runtime::SessionRegistry Registry;
        std::shared_ptr<Prism::Runtime::SessionControl> Control;
        std::optional<Prism::Runtime::SessionRegistry::Registration> Registration;
        std::shared_ptr<Prism::Contract::MuxSession> Owner;
        Net::experimental::channel<void(boost::system::error_code)> ChildDone;
        std::map<std::int32_t, std::vector<std::byte>> Replies;
        std::int32_t FirstStreamId{-1}, SecondStreamId{-1}, ReplacementStreamId{-1};
        std::size_t ExpectedConnections{1};
        bool Silent{false}, ReadFinished{false}, ResetFirstStream{false};
        std::size_t Reports{0};
    };
    class Outbound final : public Prism::Transmission
    {
    public:
        Outbound(Prism::SharedTransmission Raw, std::weak_ptr<Fixture> State)
            : Prism::Transmission(Raw->Executor()), Raw_(std::move(Raw)), State_(std::move(State))
        {
        }
        auto Executor() const -> Net::any_io_executor override { return Raw_->Executor(); }
        auto StartRead(std::span<std::byte> Bytes, Completion Handler) -> void override
        {
            Initiate<ReadWork>(ReadInput{std::static_pointer_cast<Outbound>(
                Prism::Transmission::shared_from_this()), Bytes}, std::move(Handler));
        }
        auto StartWrite(std::span<const std::byte> Bytes, Completion Handler) -> void override
        {
            Initiate<WriteWork>(WriteInput{std::static_pointer_cast<Outbound>(
                Prism::Transmission::shared_from_this()), Bytes}, std::move(Handler));
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Raw_->WriteShutdown(std::move(Handler)); }
        auto IsOpen() const -> bool override { return Raw_->IsOpen(); }
        [[nodiscard]] auto OnClose() -> ControlResult override { return Raw_->Close(); }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return Raw_->Cancel(); }
    private:
        struct ReadInput final { std::shared_ptr<Outbound> Owner; std::span<std::byte> Bytes; };
        struct WriteInput final { std::shared_ptr<Outbound> Owner; std::span<const std::byte> Bytes; };
        struct ReadWork final
        {
            template<class StateValue>
            auto operator()(StateValue Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Bytes), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct WriteWork final
        {
            template<class StateValue>
            auto operator()(StateValue Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Bytes), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Bytes)
            -> Net::awaitable<Prism::IoResult>
        {
            auto Result = co_await Raw_->ReadSome(Bytes);
            if (Result.Bytes == 0 || Result.Failure.Failed())
            {
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                Net::steady_timer Cleanup(co_await Net::this_coro::executor);
                Cleanup.expires_after(std::chrono::milliseconds(50));
                co_await Cleanup.async_wait(Net::use_awaitable);
                if (const auto State = State_.lock()) State->ReadFinished = true;
            }
            co_return Result;
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Bytes)
            -> Net::awaitable<Prism::IoResult>
        { co_return co_await Raw_->WriteSome(Bytes); }
        Prism::SharedTransmission Raw_;
        std::weak_ptr<Fixture> State_;
    };
    class Egress final : public Prism::Contract::StreamEgress
    {
    public:
        explicit Egress(std::weak_ptr<Fixture> State) : State_(std::move(State)) {}
        auto Connect(Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>> override
        {
            if (const auto State = State_.lock()) ++State->Dials;
            else co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code Error;
            co_await Socket.async_connect(Tcp::endpoint(*Prism::Network::IpAddress(Target.Host),
                Target.Port),
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::Unreachable, static_cast<std::error_code>(Error)});
            Prism::SharedTransmission Value = std::make_shared<Outbound>(
                std::make_shared<Prism::Transport::Reliable>(std::move(Socket)), State_);
            if (const auto State = State_.lock()) State->WeakOutbound = Value;
            co_return Value;
        }
    private:
        std::weak_ptr<Fixture> State_;
    };
    auto Echo(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        while (State->TargetConnections < State->ExpectedConnections)
        {
            Error.clear();
            co_await State->Acceptor.async_accept(State->Target, Net::redirect_error(Net::use_awaitable, Error));
            if (Error) co_return;
            std::array<char, Payload.size()> Data{};
            State->TargetBytes += co_await Net::async_read(State->Target, Net::buffer(Data),
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) co_return;
            EXPECT_EQ(std::string_view(Data.data(), Data.size()), Payload);
            (void)co_await Net::async_write(State->Target, Net::buffer(Data),
                Net::redirect_error(Net::use_awaitable, Error));
            std::array<char, 1> Pending{};
            (void)co_await State->Target.async_read_some(
                Net::buffer(Pending), Net::redirect_error(Net::use_awaitable, Error));
            ++State->TargetConnections;
            State->Target.close(Error);
        }
    }
    auto Root(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        Prism::Trojan::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableMux = true;
        auto MuxBinding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Wire = Prism::Mux::Mode::H2Mux,
            .Services = {
                .Egress = std::make_shared<Egress>(State),
                .Bytes = std::make_shared<Prism::Memory::BytePool>(
                    Prism::Memory::BytePoolOptions{.BlockCount = 32})},
            .GenerationUseState = State->UseState,
            .Observe = [Weak = std::weak_ptr<Fixture>(State)](Prism::Mux::ChildReport Report)
            {
                if (const auto Value = Weak.lock())
                {
                    ++Value->Reports;
                    if (!Report.Target.Host.Empty())
                        (void)Value->ChildDone.try_send(boost::system::error_code{});
                }
            }});
        auto Prepared = Prism::Trojan::PrepareProviderBinding(Prism::Trojan::ProviderRequest{
            .Instance = "mux-h2-root-test",
            .Authentication = {State->Directory->Generation, State->Directory->Credentials,
                State->Directory->Authenticator},
            .Datagrams = {}, .GenerationUseState = State->UseState,
            .Executor = State->Client->Executor(), .EnableTcp = Config.EnableTcp,
            .EnableUdp = Config.EnableUdp, .EnableMux = Config.EnableMux});
        if (!Prepared)
        {
            ADD_FAILURE() << "Trojan provider binding preparation failed";
            co_return;
        }
        const auto ProviderBinding = Prism::Trojan::BindProvider(std::move(*Prepared));
        const auto Factory = ProviderBinding->WithIngress({.Mux = MuxBinding});
        if (!Factory)
        {
            ADD_FAILURE() << "Trojan mux ingress binding failed";
            co_return;
        }
        auto Input = MakeStreamAcceptInput(std::move(State->Server));
        auto Plane = co_await Factory->Accept(std::move(Input));
        State->Authenticated = Plane && bool(Plane->AccountLease);
        if (!Plane) co_return;
        State->Server = Plane->Transport();
        State->Owner = Plane->Mux()->Session; State->WeakRoot = State->Owner;
        Prism::Contract::MuxRootRequest Request;
        Request.Metadata.TaskIdentity.TaskId = Prism::TaskId{501};
        Request.Metadata.TaskIdentity.SessionId = Prism::SessionId{4402};
        Request.Metadata.TaskIdentity.WorkerId = Prism::WorkerId{2};
        Request.Metadata.TaskIdentity.Generation = Prism::GenerationId{3};
        State->Control = std::make_shared<Prism::Runtime::SessionControl>(
            State->Client->Executor());
        Prism::Runtime::SessionInfo Info;
        Info.Id = 4402U;
        Info.AccountId = Prism::AccountId{4402};
        Info.AccountRuntime = Prism::Account::AccountRuntime{
            Info.AccountId, 1}.RuntimeIdentity();
        Info.Worker = Prism::WorkerId{2};
        Info.Generation = Prism::GenerationId{3};
        auto Registered = State->Registry.Register(Info, State->Control);
        if (!Registered)
        {
            ADD_FAILURE() << "session registry rejected the live H2 root identity";
            co_return;
        }
        State->Registration.emplace(std::move(Registered));
        if (!State->Control->SetIdentity(Request.Metadata.TaskIdentity) ||
            !State->Control->AttachStreamCatalog(State->Catalog))
        {
            ADD_FAILURE() << "session control could not bind the live H2 stream catalog";
            co_return;
        }
        Request.StreamCatalogOwner = State->Catalog;
        Request.Lease = std::move(Plane->AccountLease);
        Request.GenerationUseState = State->UseState;
        (void)co_await State->Owner->Run(std::move(Request));
        State->UsesAtRootReturn = State->UseState->Outstanding();
        State->ReadFinishedAtRootReturn = State->ReadFinished;
        State->ReportsAtRootReturn = State->Reports;
        State->RootFinished = true;
        State->Owner.reset(); State->Stop();
    }
    auto FlushH2Client(std::shared_ptr<Fixture> State,
                       const std::shared_ptr<Prism::Http2::Session> &H2) -> Net::awaitable<bool>
    {
        std::vector<std::byte> Wire;
        if (!H2->Collect(Wire)) co_return false;
        const auto Result = co_await State->Client->WriteExact(Wire);
        co_return !Result.Failure.Failed();
    }

    auto PumpH2(std::shared_ptr<Fixture> State,
                const std::shared_ptr<Prism::Http2::Session> &H2) -> Net::awaitable<bool>
    {
        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            const auto FirstReady = State->Replies[State->FirstStreamId].size() >= Payload.size() + 1U;
            const auto SecondReady = State->SecondStreamId < 0 ||
                !State->Replies[State->SecondStreamId].empty();
            const auto ReplacementReady = State->ReplacementStreamId < 0 ||
                State->Replies[State->ReplacementStreamId].size() >= Payload.size() + 1U;
            if (FirstReady && SecondReady && ReplacementReady) co_return true;
            const auto ReadResult = co_await State->Client->ReadSome(Buffer);
            const auto Count = ReadResult.Bytes;
            if (ReadResult.Failure.Failed() || Count == 0U) co_return false;
            std::error_code FeedError;
            if (!H2->Feed(std::span(Buffer).first(Count), FeedError) || FeedError) co_return false;
            std::vector<std::byte> Wire;
            if (H2->Collect(Wire))
            {
                const auto WriteResult = co_await State->Client->WriteExact(Wire);
                if (WriteResult.Failure.Failed()) co_return false;
            }
        }
    }

    auto RunQuotaClient(std::shared_ptr<Fixture> State,
                        const std::shared_ptr<Prism::Http2::Session> &H2) -> Net::awaitable<void>
    {
        H2->OnData = [State](const std::int32_t Id, std::span<const std::byte> Value)
        { State->Replies[Id].insert(State->Replies[Id].end(), Value.begin(), Value.end()); };
        const auto OpenedFirst = H2->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        const auto OpenedSecond = H2->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        if (!OpenedFirst || !OpenedSecond)
        {
            ADD_FAILURE() << "failed to open initial streams";
            co_return;
        }
        State->FirstStreamId = *OpenedFirst;
        State->SecondStreamId = *OpenedSecond;
        EXPECT_GT(State->FirstStreamId, 0); EXPECT_GT(State->SecondStreamId, 0);
        EXPECT_TRUE(co_await FlushH2Client(State, H2));
        const auto Port = State->Acceptor.local_endpoint().port();
        std::vector<std::byte> Request{std::byte{0}, std::byte{0}, std::byte{1}, std::byte{127},
            std::byte{0}, std::byte{0}, std::byte{1}, std::byte{static_cast<std::uint8_t>(Port >> 8)},
            std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Data = std::as_bytes(std::span(Payload));
        Request.insert(Request.end(), Data.begin(), Data.end());
        EXPECT_EQ(H2->SubmitData(State->FirstStreamId, Request, true), Prism::Http2::SubmitDataStatus::Accepted);
        EXPECT_EQ(H2->SubmitData(State->SecondStreamId, Request, true), Prism::Http2::SubmitDataStatus::Accepted);
        EXPECT_TRUE(co_await FlushH2Client(State, H2));
        EXPECT_TRUE(co_await PumpH2(State, H2));
        State->FirstEcho = State->Replies[State->FirstStreamId].size() == Payload.size() + 1U &&
            State->Replies[State->FirstStreamId][0] == std::byte{0};
        State->SecondRejected = State->Replies[State->SecondStreamId].size() == 1U &&
            State->Replies[State->SecondStreamId][0] == std::byte{1};
        State->DialsAfterSecond = State->Dials;
        co_await State->ChildDone.async_receive(Net::use_awaitable);
        State->FirstStreams = State->Record->Runtime()->ActiveStreams();

        const auto ReplacementStream = H2->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        if (!ReplacementStream)
        {
            ADD_FAILURE() << "failed to open replacement stream";
            co_return;
        }
        State->ReplacementStreamId = *ReplacementStream;
        EXPECT_GT(State->ReplacementStreamId, 0);
        EXPECT_TRUE(co_await FlushH2Client(State, H2));
        EXPECT_EQ(H2->SubmitData(State->ReplacementStreamId, Request, true), Prism::Http2::SubmitDataStatus::Accepted);
        EXPECT_TRUE(co_await FlushH2Client(State, H2));
        EXPECT_TRUE(co_await PumpH2(State, H2));
        State->ReplacementEcho = State->Replies[State->ReplacementStreamId].size() == Payload.size() + 1U &&
            State->Replies[State->ReplacementStreamId][0] == std::byte{0};
        co_await State->ChildDone.async_receive(Net::use_awaitable);
        const auto ClientClose = State->Client->Close();
        EXPECT_TRUE(ClientClose);
        const auto ClientDrain = co_await State->Client->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
    }

    auto PumpStreamReply(
        const std::shared_ptr<Fixture> &State,
        const std::shared_ptr<Prism::Http2::Session> &H2,
        const std::int32_t StreamId) -> Net::awaitable<bool>
    {
        std::array<std::byte, 4096> Buffer{};
        while (State->Replies[StreamId].size() < Payload.size() + 1U)
        {
            const auto Read = co_await State->Client->ReadSome(Buffer);
            if (Read.Failure.Failed() || Read.Bytes == 0U) co_return false;
            std::error_code FeedError;
            if (!H2->Feed(std::span(Buffer).first(Read.Bytes), FeedError) || FeedError)
                co_return false;
            std::vector<std::byte> Wire;
            if (H2->Collect(Wire))
            {
                const auto Write = co_await State->Client->WriteExact(Wire);
                if (Write.Failure.Failed()) co_return false;
            }
        }
        co_return true;
    }

    auto RunScopedResetClient(
        const std::shared_ptr<Fixture> &State,
        const std::shared_ptr<Prism::Http2::Session> &H2) -> Net::awaitable<void>
    {
        H2->OnData = [State](const std::int32_t Id, std::span<const std::byte> Value)
        { State->Replies[Id].insert(State->Replies[Id].end(), Value.begin(), Value.end()); };
        H2->OnStreamClose = [State](const Prism::Http2::StreamReceiveClosure &Closure)
        {
            if (Closure.StreamId == State->FirstStreamId)
            {
                State->FirstResetObserved =
                    Closure.Kind == Prism::Http2::StreamReceiveClosureKind::Reset;
                State->FirstClosureKind = Closure.Kind;
                State->FirstResetCode = Closure.ErrorCode;
            }
        };
        const auto OpenedFirst = H2->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        const auto OpenedSecond = H2->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        if (!OpenedFirst || !OpenedSecond)
        {
            ADD_FAILURE() << "failed to open initial streams";
            co_return;
        }
        State->FirstStreamId = *OpenedFirst;
        State->SecondStreamId = *OpenedSecond;
        EXPECT_GT(State->FirstStreamId, 0);
        EXPECT_GT(State->SecondStreamId, 0);
        EXPECT_TRUE(co_await FlushH2Client(State, H2));
        const auto Port = State->Acceptor.local_endpoint().port();
        std::vector<std::byte> Request{
            std::byte{0}, std::byte{0}, std::byte{1}, std::byte{127}, std::byte{0},
            std::byte{0}, std::byte{1}, std::byte{static_cast<std::uint8_t>(Port >> 8)},
            std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Data = std::as_bytes(std::span(Payload));
        Request.insert(Request.end(), Data.begin(), Data.end());
        EXPECT_EQ(H2->SubmitData(State->FirstStreamId, Request, false), Prism::Http2::SubmitDataStatus::Accepted);
        EXPECT_EQ(H2->SubmitData(State->SecondStreamId, Request, false), Prism::Http2::SubmitDataStatus::Accepted);
        EXPECT_TRUE(co_await FlushH2Client(State, H2));
        EXPECT_TRUE(co_await PumpStreamReply(State, H2, State->FirstStreamId));

        const Prism::Contract::Ingress::StreamIdentity FirstIdentity{
            Prism::SessionId{4402}, Prism::WorkerId{2}, Prism::GenerationId{3},
            Prism::StreamId{static_cast<std::uint64_t>(State->FirstStreamId)}};
        const auto First = State->Catalog->Find(FirstIdentity);
        if (First.Status != Prism::Contract::Ingress::StreamCatalogStatus::Found)
        {
            ADD_FAILURE() << "accepted H2 child is absent from its parent stream catalog";
            co_return;
        }
        const Prism::Contract::Ingress::StreamResetRequest Reset{
            FirstIdentity, First.Value.Task, First.Value.ParentTask};
        const auto ResetResult = co_await State->Registry.ResetStreamAndDrain(Reset);
        State->StreamResetCompleted = bool(ResetResult);
        EXPECT_EQ(State->Catalog->Find(FirstIdentity).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::NotFound);
        const Prism::Contract::Ingress::StreamIdentity SecondIdentity{
            Prism::SessionId{4402}, Prism::WorkerId{2}, Prism::GenerationId{3},
            Prism::StreamId{static_cast<std::uint64_t>(State->SecondStreamId)}};
        EXPECT_EQ(State->Catalog->Find(SecondIdentity).Status,
            Prism::Contract::Ingress::StreamCatalogStatus::Found);
        EXPECT_TRUE(co_await PumpStreamReply(State, H2, State->SecondStreamId));
        State->SiblingSurvived =
            State->Replies[State->SecondStreamId].size() == Payload.size() + 1U;
        State->UsesWithSibling = State->UseState->Outstanding();
        const auto Closed = State->Client->Close();
        EXPECT_TRUE(Closed);
        const auto Drained = co_await State->Client->Activity()->Drain();
        EXPECT_TRUE(Drained);
    }

    auto Client(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        const auto Auth = Prism::Trojan::BuildRequest(Prism::Trojan::Credential("task4-h2"),
            Prism::Trojan::Command::Mux, {Prism::Trojan::AddressType::Domain, "root.test", 443});
        const auto AuthWrite = co_await State->Client->WriteExact(std::as_bytes(std::span(Auth)));
        EXPECT_FALSE(AuthWrite.Failure.Failed());
        const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{2}};
        const auto EnvelopeWrite = co_await State->Client->WriteExact(Envelope);
        EXPECT_FALSE(EnvelopeWrite.Failure.Failed());
        auto H2 = std::make_shared<Prism::Http2::Session>(State->Client->Executor(), false);
        H2->SendSettings();
        if (State->ResetFirstStream)
        {
            co_await RunScopedResetClient(State, H2);
            co_return;
        }
        if (State->Record->Policy()->Quota().MaxStreams == 1U)
        {
            co_await RunQuotaClient(State, H2);
            co_return;
        }
        if (State->Silent)
        {
            const auto SilentStream = H2->OpenStream(
                Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
            if (!SilentStream)
            {
                ADD_FAILURE() << "failed to open silent stream";
                co_return;
            }
        }
        const auto OpenedStream = H2->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        if (!OpenedStream)
        {
            ADD_FAILURE() << "failed to open transfer stream";
            co_return;
        }
        const auto Id = *OpenedStream;
        const auto Port = State->Acceptor.local_endpoint().port();
        std::vector<std::byte> Request{std::byte{0},std::byte{0},std::byte{1},std::byte{127},std::byte{0},
            std::byte{0},std::byte{1},std::byte{static_cast<std::uint8_t>(Port >> 8)},std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Data = std::as_bytes(std::span(Payload)); Request.insert(Request.end(), Data.begin(), Data.end());
        EXPECT_EQ(H2->SubmitData(Id, Request, false), Prism::Http2::SubmitDataStatus::Accepted);
        std::vector<std::byte> EchoBytes;
        H2->OnData = [&EchoBytes, Id](std::int32_t ReceivedId, std::span<const std::byte> Value)
        { if (Id == ReceivedId) EchoBytes.insert(EchoBytes.end(), Value.begin(), Value.end()); };
        std::vector<std::byte> Wire;
        (void)H2->Collect(Wire);
        const auto WireWrite = co_await State->Client->WriteExact(Wire);
        EXPECT_FALSE(WireWrite.Failure.Failed());
        std::array<std::byte, 4096> Buffer{};
        while (EchoBytes.size() < Payload.size() + 1)
        {
            const auto ReadResult = co_await State->Client->ReadSome(Buffer);
            const auto Count = ReadResult.Bytes;
            if (ReadResult.Failure.Failed() || Count == 0) break;
            std::error_code FeedError;
            EXPECT_TRUE(H2->Feed(std::span(Buffer).first(Count), FeedError));
            Wire.clear();
            if (H2->Collect(Wire))
            {
                const auto FrameWrite = co_await State->Client->WriteExact(Wire);
                EXPECT_FALSE(FrameWrite.Failure.Failed());
            }
        }
        State->Echo = EchoBytes.size() == Payload.size() + 1 && EchoBytes[0] == std::byte{0} &&
            std::equal(EchoBytes.begin() + 1, EchoBytes.end(), Data.begin());
        const auto ClientClose = State->Client->Close();
        EXPECT_TRUE(ClientClose);
        const auto ClientDrain = co_await State->Client->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
    }
    auto Watchdog(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        State->Deadline.expires_after(std::chrono::seconds(3));
        boost::system::error_code Error;
        co_await State->Deadline.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error) { ADD_FAILURE() << "实际 H2 根未在期限内完成"; State->Stop(); }
    }
    auto Scenario(bool Silent, const std::size_t MaxStreams = 4U) -> Result
    {
        Net::io_context Io;
        auto State = std::make_shared<Fixture>(Io.get_executor(), MaxStreams); State->Silent = Silent;
        const auto Complete = [State](std::exception_ptr Failure)
        { if (Failure) { State->Failure = Failure; State->Stop(); } };
        Net::co_spawn(Io, Root(State), Complete); Net::co_spawn(Io, Echo(State), Complete);
        Net::co_spawn(Io, Client(State), Complete); Net::co_spawn(Io, Watchdog(State), Complete);
        Io.run(); State->Owner.reset();
        return static_cast<const Result&>(*State);
    }
    auto ScopedResetScenario() -> Result
    {
        Net::io_context Io;
        auto State = std::make_shared<Fixture>(Io.get_executor(), 2U, 2U);
        State->ResetFirstStream = true;
        const auto Complete = [State](std::exception_ptr Failure)
        { if (Failure) { State->Failure = Failure; State->Stop(); } };
        Net::co_spawn(Io, Root(State), Complete);
        Net::co_spawn(Io, Echo(State), Complete);
        Net::co_spawn(Io, Client(State), Complete);
        Net::co_spawn(Io, Watchdog(State), Complete);
        Io.run();
        State->Owner.reset();
        return static_cast<const Result&>(*State);
    }

    class ResetReadTransmission final : public Prism::Transmission
    {
    public:
        explicit ResetReadTransmission(Net::any_io_executor Executor)
            : Prism::Transmission(std::move(Executor))
        {
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t
        {
            return ReadCount_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto WriteCount() const noexcept -> std::size_t
        {
            return WriteCount_.load(std::memory_order_acquire);
        }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            ReadCount_.fetch_add(1U, std::memory_order_acq_rel);
            const auto Failure = Prism::Fault::FromNative(
                std::make_error_code(std::errc::connection_reset));
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0U, Failure});
        }

        auto StartWrite(std::span<const std::byte> Bytes, Completion Handler) -> void override
        {
            WriteCount_.fetch_add(1U, std::memory_order_acq_rel);
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Bytes.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {0U, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_.store(true, std::memory_order_release);
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::atomic<std::size_t> ReadCount_{0U};
        std::atomic<std::size_t> WriteCount_{0U};
        std::atomic<bool> Closed_{false};
    };

    struct ReadResetOutcome final
    {
        Prism::Fault::Failure RunFailure;
        Prism::Fault::Failure DrainFailure;
        std::size_t ReadCount{0U};
        std::size_t WriteCount{0U};
        bool ServerRetired{false};
        bool RawClosed{false};
    };

    auto RunHttp2ReadReset(Net::any_io_executor Executor) -> Net::awaitable<ReadResetOutcome>
    {
        auto Raw = std::make_shared<ResetReadTransmission>(std::move(Executor));
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(Raw, 4U);
        ReadResetOutcome Outcome;
        const auto Run = co_await Server->Run();
        if (!Run) Outcome.RunFailure = Run.error();
        const auto Drain = co_await Server->Drain();
        if (!Drain) Outcome.DrainFailure = Drain.error();
        Outcome.ReadCount = Raw->ReadCount();
        Outcome.WriteCount = Raw->WriteCount();
        Outcome.ServerRetired = Server->IsRetired();
        Outcome.RawClosed = !Raw->IsOpen();
        co_return Outcome;
    }
}
TEST(MuxService, StandardH2NormalRootEofWaitsForActualChildCompletion)
{
    const auto Actual = Scenario(false);
    ASSERT_FALSE(Actual.Failure); ASSERT_TRUE(Actual.Authenticated); ASSERT_TRUE(Actual.Echo);
    EXPECT_EQ(Actual.TargetBytes, Payload.size()); EXPECT_TRUE(Actual.RootFinished);
    EXPECT_TRUE(Actual.ReadFinishedAtRootReturn); EXPECT_EQ(Actual.ReportsAtRootReturn, 1);
    EXPECT_EQ(Actual.UsesAtRootReturn, 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(), 0); EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(), 0);
    EXPECT_TRUE(Actual.WeakRoot.expired()); EXPECT_TRUE(Actual.WeakOutbound.expired());
}
TEST(MuxService, H2MuxAcceptLoopIsNotBlockedBySilentStream)
{
    const auto Actual = Scenario(true);
    ASSERT_FALSE(Actual.Failure); ASSERT_TRUE(Actual.Authenticated); ASSERT_TRUE(Actual.Echo);
    EXPECT_EQ(Actual.TargetBytes, Payload.size()); EXPECT_TRUE(Actual.RootFinished);
    EXPECT_TRUE(Actual.ReadFinishedAtRootReturn); EXPECT_EQ(Actual.ReportsAtRootReturn, 2);
    EXPECT_EQ(Actual.UsesAtRootReturn, 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(), 0); EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(), 0);
    EXPECT_TRUE(Actual.WeakRoot.expired()); EXPECT_TRUE(Actual.WeakOutbound.expired());
}

TEST(MuxService, H2QuotaRejectsSecondChildAndReopensReplacementAfterEndStream)
{
    const auto Actual = Scenario(false, 1U);
    ASSERT_FALSE(Actual.Failure); ASSERT_TRUE(Actual.Authenticated);
    EXPECT_TRUE(Actual.FirstEcho); EXPECT_TRUE(Actual.SecondRejected); EXPECT_TRUE(Actual.ReplacementEcho);
    EXPECT_EQ(Actual.DialsAfterSecond, 1U); EXPECT_EQ(Actual.Dials, 2U);
    EXPECT_EQ(Actual.FirstStreams, 0U); EXPECT_EQ(Actual.TargetConnections, 2U);
    EXPECT_EQ(Actual.TargetBytes, Payload.size() * 2U); EXPECT_TRUE(Actual.RootFinished);
    EXPECT_EQ(Actual.UsesAtRootReturn, 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(), 0U);
    EXPECT_TRUE(Actual.WeakRoot.expired()); EXPECT_TRUE(Actual.WeakOutbound.expired());
}

TEST(MuxService, H2StreamResetWaitsForSelectedChildAndKeepsSiblingAlive)
{
    const auto Actual = ScopedResetScenario();
    ASSERT_FALSE(Actual.Failure);
    ASSERT_TRUE(Actual.Authenticated);
    EXPECT_TRUE(Actual.StreamResetCompleted);
    EXPECT_TRUE(Actual.SiblingSurvived);
    // 读取点同时保留 provider accept 票据与 root 自己的一份 generation lease；
    // sibling 的 stream 配额已归还，但 root 尚未退休，因此这里应为 2。
    EXPECT_EQ(Actual.UsesWithSibling, 2U);
    EXPECT_TRUE(Actual.FirstResetObserved);
    EXPECT_EQ(Actual.FirstClosureKind, Prism::Http2::StreamReceiveClosureKind::Reset);
    EXPECT_EQ(Actual.FirstResetCode, Prism::Http2::ErrorCancel);
    EXPECT_EQ(Actual.Dials, 2U);
    EXPECT_TRUE(Actual.RootFinished);
    EXPECT_EQ(Actual.UsesAtRootReturn, 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(), 0U);
}

TEST(MuxService, H2ServerReadResetPreservesTypedFailureThroughDrain)
{
    Net::io_context Io;
    ReadResetOutcome Actual;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunHttp2ReadReset(Io.get_executor()),
        [&Actual, &Exception](std::exception_ptr Failure, ReadResetOutcome Outcome)
        {
            Exception = std::move(Failure);
            Actual = std::move(Outcome);
        });
    Io.run();

    ASSERT_FALSE(Exception);
    const auto Native = std::make_error_code(std::errc::connection_reset);
    EXPECT_EQ(Actual.RunFailure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(Actual.RunFailure.Native, Native);
    EXPECT_EQ(Actual.DrainFailure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(Actual.DrainFailure.Native, Native);
    EXPECT_EQ(Actual.ReadCount, 1U);
    EXPECT_GT(Actual.WriteCount, 0U);
    EXPECT_TRUE(Actual.ServerRetired);
    EXPECT_TRUE(Actual.RawClosed);
}
