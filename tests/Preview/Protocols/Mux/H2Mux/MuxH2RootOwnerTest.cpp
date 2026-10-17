/** @file MuxH2RootOwnerTest.cpp @brief 实际 Trojan 认证、标准 HTTP2 child 与 root completion。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Protocols/Http2/Session.hpp>
#include <Preview/Runtime/SessionRegistry.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <map>
#include <optional>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    constexpr std::string_view Payload{"A4-H2-REAL-PAYLOAD"};
    [[nodiscard]] auto MakeStreamAcceptInput(Preview::SharedTransmission Inbound)
        -> Preview::Contract::StreamAcceptInput
    {
        return {std::move(Inbound), {}, std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{.BlockCount = 8})};
    }
    struct Result
    {
        bool Authenticated{false}, Echo{false}, RootFinished{false}, ReadFinishedAtRootReturn{false};
        bool FirstEcho{false}, SecondRejected{false}, ReplacementEcho{false};
        bool StreamResetCompleted{false}, SiblingSurvived{false}, FirstResetObserved{false};
        std::uint32_t FirstResetCode{0};
        Preview::Http2::StreamReceiveClosureKind FirstClosureKind{
            Preview::Http2::StreamReceiveClosureKind::EndStream};
        std::size_t TargetBytes{0}, TargetConnections{0}, ReportsAtRootReturn{0};
        std::size_t Dials{0}, DialsAfterSecond{0}, FirstStreams{0};
        std::exception_ptr Failure;
        std::shared_ptr<const Preview::Account::AccountBinding> Record;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState{
            std::make_shared<Preview::Foundation::GenerationUseState>()};
        std::size_t UsesWithSibling{0}, UsesAtRootReturn{0};
        std::weak_ptr<Preview::Contract::MuxSession> WeakRoot;
        std::weak_ptr<Preview::Transmission> WeakOutbound;
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
            auto [C, S] = Preview::MakeMemoryPair(Ex);
            Client = std::make_shared<Preview::MemoryStream>(std::move(C));
            Server = std::make_shared<Preview::MemoryStream>(std::move(S));
            auto MutableDirectory = Preview::Testing::ProviderAccount(
                Preview::Account::Credential::Token(Preview::Trojan::Credential("task4-h2")),
                Preview::AccountId{4402}, {.MaxConnections = 1, .MaxStreams = MaxStreamsValue});
            Record = MutableDirectory->Store->FindById(Preview::AccountId{4402});
            EXPECT_TRUE(Record);
            Directory = std::move(MutableDirectory);
            Catalog = std::make_shared<Preview::Contract::Ingress::StreamCatalog>();
        }
        auto Stop() -> void
        {
            const auto ClientClose = Client->Close();
            const auto ServerClose = Server ? Server->Close() : Preview::Transmission::ControlResult{};
            if (!ClientClose || !ServerClose) Failure = std::make_exception_ptr(std::runtime_error("fixture close failed"));
            if (Owner) { Owner->Cancel(); Owner->Close(); }
            boost::system::error_code Error;
            Acceptor.close(Error); Target.close(Error); Deadline.cancel();
        }
        Tcp::acceptor Acceptor;
        Tcp::socket Target;
        Net::steady_timer Deadline;
        Preview::SharedTransmission Client, Server;
        std::shared_ptr<Preview::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Preview::Contract::Ingress::StreamCatalog> Catalog;
        Preview::Runtime::SessionRegistry Registry;
        std::shared_ptr<Preview::Runtime::SessionControl> Control;
        std::optional<Preview::Runtime::SessionRegistry::Registration> Registration;
        std::shared_ptr<Preview::Contract::MuxSession> Owner;
        Net::experimental::channel<void(boost::system::error_code)> ChildDone;
        std::map<std::int32_t, std::vector<std::byte>> Replies;
        std::int32_t FirstStreamId{-1}, SecondStreamId{-1}, ReplacementStreamId{-1};
        std::size_t ExpectedConnections{1};
        bool Silent{false}, ReadFinished{false}, ResetFirstStream{false};
        std::size_t Reports{0};
    };
    class Outbound final : public Preview::Transmission
    {
    public:
        Outbound(Preview::SharedTransmission Raw, std::weak_ptr<Fixture> State)
            : Preview::Transmission(Raw->Executor()), Raw_(std::move(Raw)), State_(std::move(State))
        {
        }
        auto Executor() const -> Net::any_io_executor override { return Raw_->Executor(); }
        auto StartRead(std::span<std::byte> Bytes, Completion Handler) -> void override
        {
            Initiate<ReadWork>(ReadInput{std::static_pointer_cast<Outbound>(
                Preview::Transmission::shared_from_this()), Bytes}, std::move(Handler));
        }
        auto StartWrite(std::span<const std::byte> Bytes, Completion Handler) -> void override
        {
            Initiate<WriteWork>(WriteInput{std::static_pointer_cast<Outbound>(
                Preview::Transmission::shared_from_this()), Bytes}, std::move(Handler));
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
                Preview::Transport::Detail::ConfigureIo(Operation);
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
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Bytes), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Bytes)
            -> Net::awaitable<Preview::IoResult>
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
            -> Net::awaitable<Preview::IoResult>
        { co_return co_await Raw_->WriteSome(Bytes); }
        Preview::SharedTransmission Raw_;
        std::weak_ptr<Fixture> State_;
    };
    class Egress final : public Preview::Contract::StreamEgress
    {
    public:
        explicit Egress(std::weak_ptr<Fixture> State) : State_(std::move(State)) {}
        auto Connect(Preview::Network::Target Target)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>> override
        {
            if (const auto State = State_.lock()) ++State->Dials;
            else co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code Error;
            co_await Socket.async_connect(Tcp::endpoint(*Preview::Network::IpAddress(Target.Host),
                Target.Port),
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) co_return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::Unreachable, static_cast<std::error_code>(Error)});
            Preview::SharedTransmission Value = std::make_shared<Outbound>(
                std::make_shared<Preview::Transport::Reliable>(std::move(Socket)), State_);
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
        Preview::Trojan::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableMux = true;
        auto MuxBinding = std::make_shared<Preview::Mux::RootBinding>(Preview::Mux::RootOptions{
            .Wire = Preview::Mux::Mode::H2Mux, .Services = {.Egress = std::make_shared<Egress>(State)},
            .GenerationUseState = State->UseState,
            .Observe = [Weak = std::weak_ptr<Fixture>(State)](Preview::Mux::ChildReport Report)
            {
                if (const auto Value = Weak.lock())
                {
                    ++Value->Reports;
                    if (!Report.Target.Host.Empty())
                        (void)Value->ChildDone.try_send(boost::system::error_code{});
                }
            }});
        auto Prepared = Preview::Trojan::PrepareProviderBinding(Preview::Trojan::ProviderRequest{
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
        const auto ProviderBinding = Preview::Trojan::BindProvider(std::move(*Prepared));
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
        Preview::Contract::MuxRootRequest Request;
        Request.Metadata.TaskIdentity.TaskId = Preview::TaskId{501};
        Request.Metadata.TaskIdentity.SessionId = Preview::SessionId{4402};
        Request.Metadata.TaskIdentity.WorkerId = Preview::WorkerId{2};
        Request.Metadata.TaskIdentity.Generation = Preview::GenerationId{3};
        State->Control = std::make_shared<Preview::Runtime::SessionControl>(
            State->Client->Executor());
        Preview::Runtime::SessionInfo Info;
        Info.Id = 4402U;
        Info.AccountId = Preview::AccountId{4402};
        Info.AccountRuntime = Preview::Account::AccountRuntime{
            Info.AccountId, 1}.RuntimeIdentity();
        Info.Worker = Preview::WorkerId{2};
        Info.Generation = Preview::GenerationId{3};
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
                       const std::shared_ptr<Preview::Http2::Session> &H2) -> Net::awaitable<bool>
    {
        std::vector<std::byte> Wire;
        if (!H2->Collect(Wire)) co_return false;
        const auto Result = co_await State->Client->WriteExact(Wire);
        co_return !Result.Failure.Failed();
    }

    auto PumpH2(std::shared_ptr<Fixture> State,
                const std::shared_ptr<Preview::Http2::Session> &H2) -> Net::awaitable<bool>
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
                        const std::shared_ptr<Preview::Http2::Session> &H2) -> Net::awaitable<void>
    {
        H2->OnData = [State](const std::int32_t Id, std::span<const std::byte> Value)
        { State->Replies[Id].insert(State->Replies[Id].end(), Value.begin(), Value.end()); };
        const auto OpenedFirst = H2->OpenStream(
            Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
        const auto OpenedSecond = H2->OpenStream(
            Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
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
        EXPECT_EQ(H2->SubmitData(State->FirstStreamId, Request, true), Preview::Http2::SubmitDataStatus::Accepted);
        EXPECT_EQ(H2->SubmitData(State->SecondStreamId, Request, true), Preview::Http2::SubmitDataStatus::Accepted);
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
            Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
        if (!ReplacementStream)
        {
            ADD_FAILURE() << "failed to open replacement stream";
            co_return;
        }
        State->ReplacementStreamId = *ReplacementStream;
        EXPECT_GT(State->ReplacementStreamId, 0);
        EXPECT_TRUE(co_await FlushH2Client(State, H2));
        EXPECT_EQ(H2->SubmitData(State->ReplacementStreamId, Request, true), Preview::Http2::SubmitDataStatus::Accepted);
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
        const std::shared_ptr<Preview::Http2::Session> &H2,
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
        const std::shared_ptr<Preview::Http2::Session> &H2) -> Net::awaitable<void>
    {
        H2->OnData = [State](const std::int32_t Id, std::span<const std::byte> Value)
        { State->Replies[Id].insert(State->Replies[Id].end(), Value.begin(), Value.end()); };
        H2->OnStreamClose = [State](const Preview::Http2::StreamReceiveClosure &Closure)
        {
            if (Closure.StreamId == State->FirstStreamId)
            {
                State->FirstResetObserved =
                    Closure.Kind == Preview::Http2::StreamReceiveClosureKind::Reset;
                State->FirstClosureKind = Closure.Kind;
                State->FirstResetCode = Closure.ErrorCode;
            }
        };
        const auto OpenedFirst = H2->OpenStream(
            Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
        const auto OpenedSecond = H2->OpenStream(
            Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
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
        EXPECT_EQ(H2->SubmitData(State->FirstStreamId, Request, false), Preview::Http2::SubmitDataStatus::Accepted);
        EXPECT_EQ(H2->SubmitData(State->SecondStreamId, Request, false), Preview::Http2::SubmitDataStatus::Accepted);
        EXPECT_TRUE(co_await FlushH2Client(State, H2));
        EXPECT_TRUE(co_await PumpStreamReply(State, H2, State->FirstStreamId));

        const Preview::Contract::Ingress::StreamIdentity FirstIdentity{
            Preview::SessionId{4402}, Preview::WorkerId{2}, Preview::GenerationId{3},
            Preview::StreamId{static_cast<std::uint64_t>(State->FirstStreamId)}};
        const auto First = State->Catalog->Find(FirstIdentity);
        if (First.Status != Preview::Contract::Ingress::StreamCatalogStatus::Found)
        {
            ADD_FAILURE() << "accepted H2 child is absent from its parent stream catalog";
            co_return;
        }
        const Preview::Contract::Ingress::StreamResetRequest Reset{
            FirstIdentity, First.Value.Task, First.Value.ParentTask};
        const auto ResetResult = co_await State->Registry.ResetStreamAndDrain(Reset);
        State->StreamResetCompleted = bool(ResetResult);
        EXPECT_EQ(State->Catalog->Find(FirstIdentity).Status,
            Preview::Contract::Ingress::StreamCatalogStatus::NotFound);
        const Preview::Contract::Ingress::StreamIdentity SecondIdentity{
            Preview::SessionId{4402}, Preview::WorkerId{2}, Preview::GenerationId{3},
            Preview::StreamId{static_cast<std::uint64_t>(State->SecondStreamId)}};
        EXPECT_EQ(State->Catalog->Find(SecondIdentity).Status,
            Preview::Contract::Ingress::StreamCatalogStatus::Found);
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
        const auto Auth = Preview::Trojan::BuildRequest(Preview::Trojan::Credential("task4-h2"),
            Preview::Trojan::Command::Mux, {Preview::Trojan::AddressType::Domain, "root.test", 443});
        const auto AuthWrite = co_await State->Client->WriteExact(std::as_bytes(std::span(Auth)));
        EXPECT_FALSE(AuthWrite.Failure.Failed());
        const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{2}};
        const auto EnvelopeWrite = co_await State->Client->WriteExact(Envelope);
        EXPECT_FALSE(EnvelopeWrite.Failure.Failed());
        auto H2 = std::make_shared<Preview::Http2::Session>(State->Client->Executor(), false);
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
                Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
            if (!SilentStream)
            {
                ADD_FAILURE() << "failed to open silent stream";
                co_return;
            }
        }
        const auto OpenedStream = H2->OpenStream(
            Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
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
        EXPECT_EQ(H2->SubmitData(Id, Request, false), Preview::Http2::SubmitDataStatus::Accepted);
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
    EXPECT_EQ(Actual.UsesWithSibling, 1U);
    EXPECT_TRUE(Actual.FirstResetObserved);
    EXPECT_EQ(Actual.FirstClosureKind, Preview::Http2::StreamReceiveClosureKind::Reset);
    EXPECT_EQ(Actual.FirstResetCode, Preview::Http2::ErrorCancel);
    EXPECT_EQ(Actual.Dials, 2U);
    EXPECT_TRUE(Actual.RootFinished);
    EXPECT_EQ(Actual.UsesAtRootReturn, 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(), 0U);
}

TEST(Http2ReceiveClosure, ResetWithNoErrorCodeRemainsReset)
{
    Net::io_context Io;
    auto Sender = std::make_shared<Preview::Http2::Session>(Io.get_executor(), false);
    auto Receiver = std::make_shared<Preview::Http2::Session>(Io.get_executor(), true);
    std::optional<Preview::Http2::StreamReceiveClosure> Closure;
    Receiver->OnStreamClose = [&Closure](const Preview::Http2::StreamReceiveClosure &Value)
    { Closure = Value; };
    Sender->SendSettings();
    const auto OpenedStream = Sender->OpenStream(
        Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
    ASSERT_TRUE(OpenedStream);
    const auto StreamId = *OpenedStream;
    std::vector<std::byte> Wire;
    ASSERT_TRUE(Sender->Collect(Wire));
    std::error_code Error;
    ASSERT_TRUE(Receiver->Feed(Wire, Error));
    ASSERT_FALSE(Error);

    ASSERT_TRUE(Sender->ResetStream(StreamId, Preview::Http2::ErrorNoError));
    Wire.clear();
    ASSERT_TRUE(Sender->Collect(Wire));
    Error.clear();
    ASSERT_TRUE(Receiver->Feed(Wire, Error));
    ASSERT_FALSE(Error);
    ASSERT_TRUE(Closure.has_value());
    EXPECT_EQ(Closure->StreamId, StreamId);
    EXPECT_EQ(Closure->Kind, Preview::Http2::StreamReceiveClosureKind::Reset);
    EXPECT_EQ(Closure->ErrorCode, Preview::Http2::ErrorNoError);
}
