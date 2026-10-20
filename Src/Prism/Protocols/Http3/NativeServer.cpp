/**
 * @file NativeServer.cpp
 * @brief HTTP/3 原生 QUIC 服务端会话 façade 的实现。
 */
#include <Prism/Protocols/Http3/NativeServer.hpp>

#include <Prism/Protocols/Http3/Detail/NativeServer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <expected>
#include <functional>
#include <limits>
#include <memory>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Http3
{
    NativeServerSession::NativeServerSession(NativeServerSessionOptions Options)
        : Owner_(std::make_shared<Detail::NativeServerSessionOwner>(std::move(Options)))
    {
    }

    NativeServerSession::~NativeServerSession() noexcept
    {
        if (Owner_)
        {
            (void)Owner_->Close();
        }
    }

    auto NativeServerSession::Run()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::unexpected(Prism::Fault::Failure{Fault::Code::Canceled});
        }
        co_return co_await Owner->Run();
    }

    auto NativeServerSession::Close() -> Prism::Transmission::ControlResult
    {
        return Owner_ ? Owner_->Close() : Prism::Transmission::ControlResult{};
    }

    auto NativeServerSession::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        co_return co_await Owner->Drain();
    }

    auto NativeServerSession::ProtocolReady() const noexcept -> bool
    {
        return Owner_ && Owner_->ProtocolReady();
    }

    auto NativeServerSession::IsRetired() const noexcept -> bool
    {
        return !Owner_ || Owner_->IsRetired();
    }
}

namespace Prism::Http3::Detail
{

    auto NativeServerSessionOwner::Run()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        std::expected<void, Prism::Fault::Failure> Result;
        std::exception_ptr Exception;
        try
        {
            Result = co_await RunCore();
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (Exception)
        {
            RecordFailure(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception)));
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        co_return Result;
    }

    auto NativeServerSessionOwner::RunCore()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
        if (!Tasks_.Enter())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::Canceled});
        }
        TaskReservation Reservation{Tasks_};
        Observe(NativeServerSessionStage::RunStarted);
        if (!Server_ || !Options_.OpenUnidirectional ||
            !Options_.AcceptUnidirectional || !Options_.AcceptBidirectional)
        {
            Observe(NativeServerSessionStage::Error, Fault::Code::ProtocolError);
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        const auto StreamsOpened = co_await OpenHttp3Streams();
        if (!StreamsOpened &&
            !(Closed_ && StreamsOpened.error().Code == Fault::Code::Canceled))
        {
            RecordFailure(StreamsOpened.error());
        }
        if (Closed_)
        {
            if (FirstFailure_.Failed()) co_return std::unexpected(FirstFailure_);
            if (!StreamsOpened && StreamsOpened.error().Code != Fault::Code::Canceled)
            {
                co_return std::unexpected(StreamsOpened.error());
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (!StreamsOpened)
        {
            Observe(NativeServerSessionStage::OpenHttp3Streams,
                    StreamsOpened.error().Code);
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        Observe(NativeServerSessionStage::OpenHttp3Streams);
        if (!InitializeHttp3())
        {
            Observe(NativeServerSessionStage::InitializeHttp3,
                    Fault::Code::ProtocolError);
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        Observe(NativeServerSessionStage::InitializeHttp3);
        if (!SpawnAcceptLoop(true) || !SpawnAcceptLoop(false))
        {
            RecordFailure({Fault::Code::ResourceUnavailable});
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        const auto Output = co_await NativeServerOutputDriver::Drain(*this);
        if (Closed_)
        {
            if (FirstFailure_.Failed()) co_return std::unexpected(FirstFailure_);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (!Output)
        {
            Observe(NativeServerSessionStage::DrainOutput, Output.error().Code);
            RecordFailure(Output.error());
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        for (;;)
        {
            auto Event = co_await Events_->Receive();
            if (!Event) break;
            if (Closed_ && Event->Type != EventType::Error) break;
            const auto Handled = co_await HandleEvent(*Event);
            if (!Handled)
            {
                RecordFailure(Handled.error());
                Observe(NativeServerSessionStage::Error, Handled.error().Code);
                break;
            }
            if (Closed_) break;
        }
        auto Status = Fault::Code::Success;
        if (FirstFailure_.Failed()) Status = FirstFailure_.Code;
        Observe(NativeServerSessionStage::RunFinished, Status);
        CloseOnExecutor();
        if (FirstFailure_.Failed()) co_return std::unexpected(FirstFailure_);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

} // namespace Prism::Http3::Detail

namespace Prism::Http3::Detail
{

    NativeServerSessionOwner::NativeServerSessionOwner(NativeServerSessionOptions Options)
            : Options_(std::move(Options)),
              Server_(CreateServer(Options_)),
              Events_(std::make_unique<EventQueue>(Options_.Executor)),
              Tasks_(Options_.Executor){
            PendingProviders_.reserve(HeaderLimits::MaxPendingEvents + 2U);
        }

    auto NativeServerSessionOwner::OnTrackedTaskComplete(std::exception_ptr Exception) noexcept -> void{
            if (Exception)
            {
                TaskFailed_.store(true, std::memory_order_release);
                RecordFailure(
                    Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::move(Exception)));
                CloseOnExecutor();
            }
        }

    auto NativeServerSessionOwner::OnTrackedTaskStartFailure(std::exception_ptr Exception) noexcept -> void{
            TaskFailed_.store(true, std::memory_order_release);
            RecordFailure(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception)));
            CloseOnExecutor();
        }

    [[nodiscard]] auto NativeServerSessionOwner::OpenHttp3Streams()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            for (auto &Provider : Http3Streams_)
            {
                auto Opened = co_await Options_.OpenUnidirectional();
                if (!Opened) co_return std::unexpected(Opened.error());
                Provider = std::move(*Opened);
                PendingProviders_.push_back(Provider);
                if (Closed_)
                {
                    const auto Closed = Provider->Close();
                    if (!Closed) co_return std::unexpected(Closed.error());
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::Canceled});
                }
                if (Provider->StreamId() < 0)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ProtocolError});
                }
                Streams_[Provider->StreamId()] = Provider;
                const auto Pending = std::find(
                    PendingProviders_.begin(), PendingProviders_.end(), Provider);
                if (Pending != PendingProviders_.end()) PendingProviders_.erase(Pending);
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    [[nodiscard]] auto NativeServerSessionOwner::InitializeHttp3() -> bool{
            std::size_t Index = 0;
            return Server_->Init([this, Index]() mutable -> std::int64_t {
                if (Index >= Http3Streams_.size() || !Http3Streams_[Index])
                {
                    return -1;
                }
                return Http3Streams_[Index++]->StreamId();
            });
        }

    [[nodiscard]] auto NativeServerSessionOwner::SpawnAcceptLoop(const bool Unidirectional) -> bool{
            const auto Self = shared_from_this();
            auto Work = [Self, Unidirectional]() -> Net::awaitable<void>
            {
                co_await Self->AcceptLoop(Unidirectional);
            };
            return Tasks_.Spawn(Options_.Executor, Self, std::move(Work));
        }

    [[nodiscard]] auto NativeServerSessionOwner::SpawnReadLoop(
            Prism::Quic::SharedStreamProvider Provider,
            const bool Unidirectional) -> bool{
            const auto Self = shared_from_this();
            auto Work = [Self, Provider = std::move(Provider), Unidirectional]() -> Net::awaitable<void>
            {
                co_await Self->ReadLoop(Provider, Unidirectional);
            };
            return Tasks_.Spawn(Options_.Executor, Self, std::move(Work));
        }

    [[nodiscard]] auto NativeServerSessionOwner::AcceptLoop(const bool Unidirectional) -> Net::awaitable<void>{
            using StreamFactory = std::function<Net::awaitable<std::expected<
                Prism::Quic::SharedStreamProvider, Prism::Fault::Failure>>() >;
            const StreamFactory *Accept = &Options_.AcceptBidirectional;
            if (Unidirectional) Accept = &Options_.AcceptUnidirectional;
            while (!Closed_)
            {
                auto Accepted = co_await (*Accept)();
                if (!Accepted)
                {
                    if (Closed_ && Accepted.error().Code == Fault::Code::Canceled)
                        co_return;
                    RecordFailure(Accepted.error());
                    CloseOnExecutor();
                    co_return;
                }
                auto Provider = std::move(*Accepted);
                PendingProviders_.push_back(Provider);
                if (Closed_)
                {
                    const auto Closed = Provider->Close();
                    if (!Closed) RecordFailure(Closed.error());
                    co_return;
                }
                auto PendingEvent = std::make_shared<Event>();
                PendingEvent->Type = EventType::NewStream;
                PendingEvent->Unidirectional = Unidirectional;
                PendingEvent->Provider = std::move(Provider);
                Observe(NativeServerSessionStage::NewStream, Fault::Code::Success,
                        PendingEvent->Provider->StreamId());
                if (!Publish(std::move(PendingEvent)))
                {
                    if (!Closed_)
                    {
                        CloseOnExecutor();
                    }
                    co_return;
                }
            }
        }

    [[nodiscard]] auto NativeServerSessionOwner::ReadLoop(
            const Prism::Quic::SharedStreamProvider &Provider,
            const bool Unidirectional) -> Net::awaitable<void>{
            std::array<std::byte, 16384> Buffer{};
            while (!Closed_ && Provider)
            {
                std::error_code Error;
                const auto Count = co_await Provider->Read(Buffer, Error);
                if (Closed_)
                {
                    co_return;
                }
                auto PendingEvent = std::make_shared<Event>();
                PendingEvent->Provider = Provider;
                PendingEvent->Unidirectional = Unidirectional;
                if (Count > Buffer.size())
                {
                    RecordFailure({Fault::Code::ProtocolError});
                    CloseOnExecutor();
                    co_return;
                }
                const bool Eof = Prism::Fault::ToCode(Error) == Fault::Code::Eof;
                const bool Fin = Error ? Eof : Count == 0;
                if (Error && !Eof)
                {
                    Observe(NativeServerSessionStage::Error,
                            Fault::Code::IoError, Provider->StreamId());
                    if (Count == 0)
                    {
                        PendingEvent->Error = Error;
                        RecordFailure(Prism::Fault::FromNative(Error));
                        const auto Published = Publish(std::move(PendingEvent));
                        if (!Published)
                        {
                            RecordFailure({Fault::Code::ResourceUnavailable});
                            CloseOnExecutor();
                        }
                        co_return;
                    }
                    PendingEvent->Type = EventType::Error;
                    PendingEvent->Error = Error;
                    if (!Events_->Reserve(*PendingEvent, Count))
                    {
                        RecordFailure({Fault::Code::ResourceUnavailable});
                        CloseOnExecutor();
                        co_return;
                    }
                    try
                    {
                        PendingEvent->Data.assign(
                            Buffer.begin(), Buffer.begin() + Count);
                    }
                    catch (...)
                    {
                        Events_->Release(*PendingEvent);
                        throw;
                    }
                    RecordFailure(Prism::Fault::FromNative(Error));
                    const auto Published = Publish(std::move(PendingEvent));
                    if (!Published)
                    {
                        RecordFailure({Fault::Code::ResourceUnavailable});
                        CloseOnExecutor();
                    }
                    co_return;
                }
                PendingEvent->Type = EventType::Data;
                PendingEvent->Fin = Fin;
                if (!Events_->Reserve(*PendingEvent, Count))
                {
                    RecordFailure({Fault::Code::ResourceUnavailable});
                    CloseOnExecutor();
                    co_return;
                }
                try
                {
                    PendingEvent->Data.assign(Buffer.begin(), Buffer.begin() + Count);
                }
                catch (...)
                {
                    Events_->Release(*PendingEvent);
                    throw;
                }
                Observe(NativeServerSessionStage::DataEvent,
                        Fault::Code::Success, Provider->StreamId());
                if (!Publish(std::move(PendingEvent)))
                {
                    RecordFailure({Fault::Code::ResourceUnavailable});
                    CloseOnExecutor();
                    co_return;
                }
                if (Fin) co_return;
            }
        }

    [[nodiscard]] auto NativeServerSessionOwner::Publish(std::shared_ptr<Event> Event) -> bool{
            if (!Events_ || !Event)
            {
                return false;
            }
            return Events_->Publish(std::move(Event));
        }

    [[nodiscard]] auto NativeServerSessionOwner::HandleEvent(Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            EventQueue::Reservation Reservation(*Events_, Event);
            if (Event.Type == EventType::NewStream)
            {
                co_return co_await HandleNewStream(Event);
            }
            if (Event.Type == EventType::Error || !Event.Provider)
            {
                auto Failure = Prism::Fault::Failure{Fault::Code::IoError};
                if (Event.Error) Failure = Prism::Fault::FromNative(Event.Error);
                if (!Event.Provider || !Server_)
                {
                    Observe(NativeServerSessionStage::Error, Failure.Code);
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ProtocolError});
                }
                if (!Event.Data.empty())
                {
                    const auto Code = Server_->Feed(
                        Event.Provider->StreamId(), std::move(Event.Data), false);
                    if (Code != Fault::Code::Success)
                    {
                        Observe(NativeServerSessionStage::Error, Code,
                                Event.Provider->StreamId());
                        co_return std::unexpected(
                            Prism::Fault::Failure{Fault::Code::ProtocolError});
                    }
                    while (auto Value = Server_->TakeEvent())
                    {
                        auto Action = co_await Dispatch(std::move(*Value));
                        if (Action.Response)
                        {
                            const auto SubmitCode =
                                Server_->SubmitResponse(std::move(*Action.Response));
                            if (SubmitCode != Fault::Code::Success)
                            {
                                Observe(NativeServerSessionStage::SubmitResponse,
                                        SubmitCode, Event.Provider->StreamId());
                                co_return std::unexpected(
                                    Prism::Fault::Failure{SubmitCode});
                            }
                        }
                        Modes_[Event.Provider->StreamId()] = Action.Mode;
                    }
                    const auto Output = co_await NativeServerOutputDriver::Drain(*this);
                    if (!Output && Output.error().Code != Fault::Code::Canceled)
                    {
                        co_return std::unexpected(Output.error());
                    }
                }
                Observe(NativeServerSessionStage::Error, Failure.Code);
                co_return std::unexpected(Failure);
            }
            if (!Event.Unidirectional && Modes_[Event.Provider->StreamId()] == StreamMode::Opaque)
            {
                auto Action = co_await Dispatch(DataEvent{
                    Event.Provider->StreamId(), std::move(Event.Data), Event.Fin});
                if (Closed_)
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                if (Action.Response)
                {
                    const auto SubmitCode = Server_->SubmitResponse(std::move(*Action.Response));
                    if (SubmitCode != Fault::Code::Success)
                    {
                        Observe(NativeServerSessionStage::SubmitResponse,
                                SubmitCode, Event.Provider->StreamId());
                        co_return std::unexpected(
                            Prism::Fault::Failure{SubmitCode});
                    }
                    Observe(NativeServerSessionStage::SubmitResponse,
                            Fault::Code::Success, Event.Provider->StreamId());
                    co_return co_await NativeServerOutputDriver::Drain(*this);
                }
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            const auto Code = Server_->Feed(
                Event.Provider->StreamId(), std::move(Event.Data), Event.Fin);
            if (Code != Fault::Code::Success)
            {
                Observe(NativeServerSessionStage::Error, Code,
                        Event.Provider->StreamId());
                co_return std::unexpected(Prism::Fault::Failure{Code});
            }
            while (auto Value = Server_->TakeEvent())
            {
                auto Action = co_await Dispatch(std::move(*Value));
                if (Closed_)
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                if (Action.Response)
                {
                    const auto SubmitCode = Server_->SubmitResponse(std::move(*Action.Response));
                    if (SubmitCode != Fault::Code::Success)
                    {
                        Observe(NativeServerSessionStage::SubmitResponse,
                                SubmitCode, Event.Provider->StreamId());
                        co_return std::unexpected(
                            Prism::Fault::Failure{SubmitCode});
                    }
                    Observe(NativeServerSessionStage::SubmitResponse,
                            Fault::Code::Success, Event.Provider->StreamId());
                }
                Modes_[Event.Provider->StreamId()] = Action.Mode;
            }
            co_return co_await NativeServerOutputDriver::Drain(*this);
        }

    auto NativeServerSessionOwner::PruneClosedStreams() -> void{
            auto It = Streams_.begin();
            while (It != Streams_.end())
            {
                if (!It->second)
                {
                    Modes_.erase(It->first);
                    It = Streams_.erase(It);
                }
                else
                {
                    const auto Activity = It->second->Activity();
                    if (Activity && Activity->IsRetired())
                    {
                        Modes_.erase(It->first);
                        It = Streams_.erase(It);
                    }
                    else
                    {
                        ++It;
                    }
                }
            }
        }

    [[nodiscard]] auto NativeServerSessionOwner::HasStreamCapacity() const noexcept -> bool{
            std::size_t LocalStreams = 0;
            for (const auto &Provider : Http3Streams_)
            {
                if (Provider && Streams_.contains(Provider->StreamId()))
                    ++LocalStreams;
            }
            if (Options_.MaxConcurrentStreams >
                (std::numeric_limits<std::size_t>::max)() - LocalStreams)
            {
                return false;
            }
            return Streams_.size() < Options_.MaxConcurrentStreams + LocalStreams;
        }

    [[nodiscard]] auto NativeServerSessionOwner::HandleNewStream(const Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            PruneClosedStreams();
            if (!Event.Provider || Event.Provider->StreamId() < 0 ||
                Streams_.contains(Event.Provider->StreamId()))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Fault::Code::ProtocolError});
            }
            if (!HasStreamCapacity())
            {
                const auto Closed = Event.Provider->Close();
                if (!Closed) co_return std::unexpected(Closed.error());
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            const auto StreamId = Event.Provider->StreamId();
            Streams_[StreamId] = Event.Provider;
            const auto Pending = std::find(
                PendingProviders_.begin(), PendingProviders_.end(), Event.Provider);
            if (Pending != PendingProviders_.end()) PendingProviders_.erase(Pending);
            Modes_[StreamId] = StreamMode::Http3;
            if (!Event.Unidirectional)
            {
                auto Action = co_await Dispatch(RawStreamEvent{
                    StreamId, StreamDirection::Inbound, Event.Provider});
                if (Closed_)
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                Modes_[StreamId] = Action.Mode;
                if (Action.Mode == StreamMode::Opaque)
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
            }
            if (!SpawnReadLoop(Event.Provider, Event.Unidirectional))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Fault::Code::ResourceUnavailable});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    [[nodiscard]] auto NativeServerSessionOwner::Dispatch(ServerEvent Event) -> Net::awaitable<SessionAction>{
            const auto StreamId = std::visit(
                [](const auto &Value) -> std::int64_t
                {
                    if constexpr (requires { Value.StreamId; })
                    {
                        return Value.StreamId;
                    }
                    return -1;
                },
                Event);
            auto Stage = NativeServerSessionStage::NewStream;
            if (std::holds_alternative<RequestEvent>(Event))
            {
                Stage = NativeServerSessionStage::RequestEvent;
            }
            else if (std::holds_alternative<DataEvent>(Event))
            {
                Stage = NativeServerSessionStage::DataEvent;
            }
            Observe(Stage, Fault::Code::Success, StreamId);
            if (!Options_.OnEvent)
            {
                co_return SessionAction{};
            }
            co_return co_await Options_.OnEvent(std::move(Event));
        }

    auto NativeServerSessionOwner::Observe(const NativeServerSessionStage Stage,
                     const Fault::Code Status,
                     const std::int64_t StreamId) noexcept -> void{
            if (!Options_.Observer)
            {
                return;
            }
            try
            {
                Options_.Observer(NativeServerSessionEvent{Stage, Status, StreamId});
            }
            catch (...)
            {
            }
        }

} // namespace Prism::Http3::Detail

namespace Prism::Http3::Detail
{
    [[nodiscard]] auto NativeServerSessionOwner::CreateServer(
            const Prism::Http3::NativeServerSessionOptions &Options)
            -> Prism::Http3::SharedServer{
            if (!Options.Factory)
            {
                return nullptr;
            }
            return Options.Factory->Create(Options.Http);
        }
} // namespace Prism::Http3::Detail
