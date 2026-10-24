/**
 * @file NativeClient.cpp
 * @brief HTTP/3 原生 QUIC 客户端 façade 的实现。
 */
#include <Prism/Protocols/Http3/NativeClient.hpp>

#include <Prism/Protocols/Http3/Detail/NativeClient.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Http3
{
    NativeClientSession::NativeClientSession(NativeClientSessionOptions Options)
        : Owner_(std::make_shared<Detail::NativeClientSessionOwner>(std::move(Options)))
    {
    }

    NativeClientSession::~NativeClientSession() noexcept
    {
        if (Owner_)
        {
            (void)Owner_->Close();
        }
    }

    auto NativeClientSession::SendRequest(RequestHead Request)
        -> Net::awaitable<std::expected<ResponseHead, Prism::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::unexpected(Prism::Fault::Failure{Fault::Code::InvalidArgument});
        }
        co_return co_await Owner->SendRequest(std::move(Request));
    }

    auto NativeClientSession::OpenBidirectionalStream()
        -> Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                        Prism::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::unexpected(Prism::Fault::Failure{Fault::Code::InvalidArgument});
        }
        co_return co_await Owner->OpenBidirectionalStream();
    }

    auto NativeClientSession::Close() -> Prism::Transmission::ControlResult
    {
        return Owner_ ? Owner_->Close() : Prism::Transmission::ControlResult{};
    }

    auto NativeClientSession::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        co_return co_await Owner->Drain();
    }

    auto NativeClientSession::HandshakeReady() const noexcept -> bool
    {
        return Owner_ && Owner_->HandshakeReady();
    }

    auto NativeClientSession::ProtocolReady() const noexcept -> bool
    {
        return Owner_ && Owner_->ProtocolReady();
    }

    auto NativeClientSession::IsRetired() const noexcept -> bool
    {
        return !Owner_ || Owner_->IsRetired();
    }
}

namespace Prism::Http3::Detail
{

    auto NativeClientSessionOwner::SendRequest(RequestHead Request)
        -> Net::awaitable<std::expected<ResponseHead, Prism::Fault::Failure>>{
        std::optional<std::expected<ResponseHead, Prism::Fault::Failure>> Result;
        std::exception_ptr Exception;
        try
        {
            Result.emplace(co_await SendRequestCore(std::move(Request)));
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (Exception)
        {
            const auto Failure =
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
            RecordFailure(Failure);
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Failure.Code));
        }
        co_return std::move(*Result);
    }

    auto NativeClientSessionOwner::SendRequestCore(RequestHead Request)
        -> Net::awaitable<std::expected<ResponseHead, Prism::Fault::Failure>>{
        co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
        if (!Tasks_.Enter())
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        TaskReservation Reservation{Tasks_};
        if (RequestActive_ || (RequestStream_ && !ResponseDone_))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::ResourceUnavailable});
        }
        RequestReservation RequestSlot{RequestActive_};
        ResponseHeaders_.Clear();
        ResponseStatus_ = 0;
        ResponseHeadersDone_ = false;
        ResponseDone_ = false;
        ResponseFin_ = false;
        ResponseStreamId_ = -1;
        if (!Options_.Connection)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::InvalidArgument});
        }
        const auto Setup = co_await EnsureReady();
        if (Closed_)
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        if (!Setup)
        {
            RecordFailure(Setup.error());
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Setup.error().Code));
        }
        auto Opened = co_await Options_.Connection->OpenBidirectionalStream();
        if (!Opened)
        {
            co_return std::unexpected(Opened.error());
        }
        RequestStream_ = std::move(*Opened);
        TrackPendingProvider(RequestStream_);
        if (Closed_)
        {
            const auto Closed = RequestStream_->Close();
            if (!Closed) RecordFailure(Closed.error());
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        if (RequestStream_->StreamId() < 0)
        {
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(
                CurrentFailure(Fault::Code::ProtocolError));
        }
        Streams_[RequestStream_->StreamId()] = RequestStream_;
        ForgetPendingProvider(RequestStream_);
        RequestStreamId_ = RequestStream_->StreamId();
        RequestHeaders_.emplace(std::move(Request.Headers));
        RequestFin_ = Request.Fin;
        if (!NativeClientCallbacks::Submit(*this))
        {
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Fault::Code::ProtocolError));
        }
        if (!SpawnReadLoop(RequestStream_))
        {
            RecordFailure({Fault::Code::ResourceUnavailable});
            CloseOnExecutor();
            co_return std::unexpected(
                CurrentFailure(Fault::Code::ResourceUnavailable));
        }
        const auto Output = co_await DrainOutput();
        if (Closed_)
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        if (!Output)
        {
            RecordFailure(Output.error());
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Output.error().Code));
        }
        co_return co_await ReceiveResponse();
    }

    auto NativeClientSessionOwner::EnsureReady()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        if (Closed_ || !Options_.Connection)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::Canceled});
        }
        if (Ready_)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        Options_.Connection->Start();
        if (!co_await Options_.Connection->WaitHandshake())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::TlsHsfail});
        }
        if (Closed_)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::Canceled});
        }
        const auto Opened = co_await OpenInitialStreams();
        if (!Opened) co_return std::unexpected(Opened.error());
        if (Closed_)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::Canceled});
        }
        if (!InitializeHttp3())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::ProtocolError});
        }
        if (!SpawnAcceptLoop())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::ResourceUnavailable});
        }
        Ready_ = true;
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto NativeClientSessionOwner::OpenInitialStreams()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        for (auto &Provider : Http3Streams_)
        {
            auto Opened = co_await Options_.Connection->OpenUnidirectionalStream();
            if (!Opened)
            {
                RecordFailure(Opened.error());
                co_return std::unexpected(Opened.error());
            }
            Provider = std::move(*Opened);
            TrackPendingProvider(Provider);
            if (Closed_)
            {
                const auto Closed = Provider->Close();
                if (!Closed)
                {
                    RecordFailure(Closed.error());
                    co_return std::unexpected(Closed.error());
                }
                co_return std::unexpected(
                    Prism::Fault::Failure{Fault::Code::Canceled});
            }
            if (Provider->StreamId() < 0)
            {
                RecordFailure({Fault::Code::ProtocolError});
                co_return std::unexpected(
                    Prism::Fault::Failure{Fault::Code::ProtocolError});
            }
            Streams_[Provider->StreamId()] = Provider;
            ForgetPendingProvider(Provider);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto NativeClientSessionOwner::ReceiveResponse()
        -> Net::awaitable<std::expected<ResponseHead, Prism::Fault::Failure>>{
        while (!ResponseHeadersDone_)
        {
            auto Event = co_await Events_->Receive();
            if (!Event)
            {
                if (Closed_)
                {
                    co_return std::unexpected(
                        CurrentFailure(Fault::Code::Canceled));
                }
                co_return std::unexpected(CurrentFailure(Fault::Code::IoError));
            }
            if (Closed_ && Event->Type != EventType::Error)
            {
                co_return std::unexpected(
                    CurrentFailure(Fault::Code::Canceled));
            }
            const auto Handled = co_await HandleEvent(*Event);
            if (!Handled)
            {
                RecordFailure(Handled.error());
                CloseOnExecutor();
                co_return std::unexpected(CurrentFailure(Handled.error().Code));
            }
        }
        if (Closed_ || !ResponseHeadersDone_)
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        auto Headers = std::move(ResponseHeaders_);
        co_return ResponseHead{
            RequestStreamId_, ResponseStatus_, std::move(Headers), ResponseFin_};
    }

    auto NativeClientSessionOwner::OpenBidirectionalStream()
        -> Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                        Prism::Fault::Failure>>{
        std::optional<std::expected<Prism::Quic::SharedStreamProvider,
                                    Prism::Fault::Failure>> Result;
        std::exception_ptr Exception;
        try
        {
            Result.emplace(co_await OpenBidirectionalStreamCore());
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (Exception)
        {
            const auto Failure =
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
            RecordFailure(Failure);
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Failure.Code));
        }
        co_return std::move(*Result);
    }

    auto NativeClientSessionOwner::OpenBidirectionalStreamCore()
        -> Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                        Prism::Fault::Failure>>{
        co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
        if (!Tasks_.Enter())
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        TaskReservation Reservation{Tasks_};
        if (Closed_ || !Ready_ || !Options_.Connection)
        {
            auto Code = Fault::Code::InvalidArgument;
            if (Closed_) Code = Fault::Code::Canceled;
            co_return std::unexpected(CurrentFailure(Code));
        }
        auto Opened = co_await Options_.Connection->OpenBidirectionalStream();
        if (!Opened)
        {
            co_return std::unexpected(Opened.error());
        }
        auto Provider = std::move(*Opened);
        TrackPendingProvider(Provider);
        if (Closed_)
        {
            const auto Closed = Provider->Close();
            if (!Closed) RecordFailure(Closed.error());
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        if (Provider->StreamId() < 0)
        {
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(
                CurrentFailure(Fault::Code::ProtocolError));
        }
        ForgetPendingProvider(Provider);
        co_return Provider;
    }

} // namespace Prism::Http3::Detail

namespace Prism::Http3::Detail
{

    NativeClientSessionOwner::NativeClientSessionOwner(Prism::Http3::NativeClientSessionOptions Options)
            : Options_(std::move(Options)),
              Events_(std::make_unique<BoundedEventQueue<Event>>(Options_.Executor)),
              Tasks_(Options_.Executor){
            PendingProviders_.reserve(HeaderLimits::MaxPendingEvents + 1U);
        }

    [[nodiscard]] auto NativeClientSessionOwner::SpawnAcceptLoop() -> bool{
            const auto Self = shared_from_this();
            auto Work = [Self]() -> Net::awaitable<void> { co_await Self->AcceptLoop(); };
            return Tasks_.Spawn(Options_.Executor, Self, std::move(Work));
        }

    [[nodiscard]] auto NativeClientSessionOwner::SpawnReadLoop(Prism::Quic::SharedStreamProvider Provider) -> bool{
            const auto Self = shared_from_this();
            auto Work = [Self, Provider = std::move(Provider)]() -> Net::awaitable<void>
            {
                co_await Self->ReadLoop(Provider);
            };
            return Tasks_.Spawn(Options_.Executor, Self, std::move(Work));
        }

    auto NativeClientSessionOwner::OnTrackedTaskComplete(std::exception_ptr Exception) noexcept -> void{
            if (Exception)
            {
                TaskFailed_.store(true, std::memory_order_release);
                RecordFailure(
                    Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::move(Exception)));
                CloseOnExecutor();
            }
        }

    auto NativeClientSessionOwner::OnTrackedTaskStartFailure(std::exception_ptr Exception) noexcept -> void{
            TaskFailed_.store(true, std::memory_order_release);
            RecordFailure(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception)));
            CloseOnExecutor();
        }

    auto NativeClientSessionOwner::RecordFailure(Prism::Fault::Failure Failure) noexcept -> void{
            if (!FirstFailure_.Failed() && Failure.Failed()) FirstFailure_ = Failure;
        }

    auto NativeClientSessionOwner::TrackPendingProvider(
            const Prism::Quic::SharedStreamProvider &Provider) -> void{
            if (std::find(PendingProviders_.begin(),
                          PendingProviders_.end(), Provider) !=
                PendingProviders_.end())
            {
                return;
            }
            PendingProviders_.push_back(Provider);
        }

    auto NativeClientSessionOwner::ForgetPendingProvider(
            const Prism::Quic::SharedStreamProvider &Provider) -> void{
            const auto Pending = std::find(
                PendingProviders_.begin(), PendingProviders_.end(), Provider);
            if (Pending != PendingProviders_.end()) PendingProviders_.erase(Pending);
        }

    [[nodiscard]] auto NativeClientSessionOwner::InitializeHttp3() -> bool{
            return NativeClientCallbacks::Initialize(*this);
        }

    [[nodiscard]] auto NativeClientSessionOwner::SubmitRequest() -> bool{
            return NativeClientCallbacks::Submit(*this);
        }

    [[nodiscard]] auto NativeClientSessionOwner::AcceptLoop() -> Net::awaitable<void>{
            while (!Closed_ && Options_.Connection)
            {
                auto Accepted = co_await Options_.Connection->AcceptUnidirectionalStream();
                if (!Accepted)
                {
                    if (Closed_ && Accepted.error().Code == Fault::Code::Canceled)
                        co_return;
                    RecordFailure(Accepted.error());
                    CloseOnExecutor();
                    co_return;
                }
                auto Provider = std::move(*Accepted);
                TrackPendingProvider(Provider);
                if (Closed_)
                {
                    const auto Closed = Provider->Close();
                    if (!Closed) RecordFailure(Closed.error());
                    co_return;
                }
                auto PendingEvent = std::make_shared<Event>();
                PendingEvent->Type = EventType::NewStream;
                PendingEvent->Provider = Provider;
                if (!Publish(std::move(PendingEvent)))
                {
                    CloseOnExecutor();
                    co_return;
                }
            }
        }

    [[nodiscard]] auto NativeClientSessionOwner::ReadLoop(
            const Prism::Quic::SharedStreamProvider &Provider) -> Net::awaitable<void>{
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
                if (!Publish(std::move(PendingEvent)))
                {
                    RecordFailure({Fault::Code::ResourceUnavailable});
                    CloseOnExecutor();
                    co_return;
                }
                if (Fin) co_return;
            }
        }

    [[nodiscard]] auto NativeClientSessionOwner::Publish(std::shared_ptr<Event> Event) -> bool{
            return !Closed_ && Events_ && Events_->Publish(std::move(Event));
        }

    auto NativeClientSessionOwner::PruneClosedStreams() -> void{
            auto It = Streams_.begin();
            while (It != Streams_.end())
            {
                if (!It->second)
                {
                    It = Streams_.erase(It);
                    continue;
                }
                const auto Activity = It->second->Activity();
                if (Activity && Activity->IsRetired())
                {
                    It = Streams_.erase(It);
                    continue;
                }
                ++It;
            }
        }

    [[nodiscard]] auto NativeClientSessionOwner::HandleEvent(Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            EventQueue::Reservation Reservation(*Events_, Event);
            if (Event.Type == EventType::NewStream)
            {
                PruneClosedStreams();
                if (!Event.Provider || Streams_.contains(Event.Provider->StreamId()))
                {
                    if (Event.Provider)
                    {
                        const auto Closed = Event.Provider->Close();
                        if (!Closed) RecordFailure(Closed.error());
                    }
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ProtocolError});
                }
                std::size_t LocalStreams = 0;
                for (const auto &Provider : Http3Streams_)
                {
                    if (Provider && Streams_.contains(Provider->StreamId()))
                        ++LocalStreams;
                }
                if (RequestStream_ &&
                    Streams_.contains(RequestStream_->StreamId()))
                {
                    ++LocalStreams;
                }
                if (Options_.MaxConcurrentStreams >
                        (std::numeric_limits<std::size_t>::max)() - LocalStreams ||
                    Streams_.size() >= Options_.MaxConcurrentStreams + LocalStreams)
                {
                    const auto Closed = Event.Provider->Close();
                    if (!Closed)
                    {
                        RecordFailure(Closed.error());
                        co_return std::unexpected(Closed.error());
                    }
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                Streams_[Event.Provider->StreamId()] = Event.Provider;
                ForgetPendingProvider(Event.Provider);
                if (!SpawnReadLoop(Event.Provider))
                {
                    const auto Closed = Event.Provider->Close();
                    if (!Closed) RecordFailure(Closed.error());
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ResourceUnavailable});
                }
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            if (Event.Type == EventType::Error)
            {
                auto Failure = Prism::Fault::Failure{Fault::Code::IoError};
                if (Event.Error) Failure = Prism::Fault::FromNative(Event.Error);
                if (!Event.Provider || !Conn_)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ProtocolError});
                }
                const auto *EventData = Event.Data.empty()
                    ? nullptr
                    : reinterpret_cast<const std::uint8_t *>(Event.Data.data());
                if (!Event.Data.empty())
                {
                    const auto Consumed = nghttp3_conn_read_stream2(
                        Conn_, Event.Provider->StreamId(), EventData,
                        Event.Data.size(), 0, NativeClientCallbacks::NowTstamp());
                    if (Consumed < 0)
                    {
                        co_return std::unexpected(
                            Prism::Fault::Failure{Fault::Code::ProtocolError});
                    }
                    const auto Output = co_await DrainOutput();
                    if (!Output && Output.error().Code != Fault::Code::Canceled)
                    {
                        co_return std::unexpected(Output.error());
                    }
                }
                co_return std::unexpected(Failure);
            }
            if (!Event.Provider || !Conn_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Fault::Code::ProtocolError});
            }
            const std::uint8_t *EventData = nullptr;
            if (!Event.Data.empty())
            {
                EventData = reinterpret_cast<const std::uint8_t *>(Event.Data.data());
            }
            const auto FinValue = static_cast<int>(Event.Fin);
            const auto Result = nghttp3_conn_read_stream2(
                Conn_, Event.Provider->StreamId(), EventData,
                Event.Data.size(), FinValue, NativeClientCallbacks::NowTstamp());
            if (Result < 0)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Fault::Code::ProtocolError});
            }
            co_return co_await DrainOutput();
        }

    [[nodiscard]] auto NativeClientSessionOwner::DrainOutput()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            while (!Closed_ && Conn_)
            {
                std::array<nghttp3_vec, 16> Vectors{};
                std::array<std::array<std::byte, 4096>, 16> Buffers{};
                for (std::size_t Index = 0; Index < Vectors.size(); ++Index)
                {
                    Vectors[Index].base = reinterpret_cast<std::uint8_t *>(Buffers[Index].data());
                    Vectors[Index].len = Buffers[Index].size();
                }
                std::int64_t StreamId = -1;
                int Fin = 0;
                const auto Count = nghttp3_conn_writev_stream(
                    Conn_, &StreamId, &Fin, Vectors.data(), Vectors.size());
                if (Count < 0 || static_cast<std::size_t>(Count) > Vectors.size())
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ProtocolError});
                }
                if (Count == 0)
                {
                    if (StreamId < 0)
                    {
                        co_return std::expected<void, Prism::Fault::Failure>{};
                    }
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ProtocolError});
                }
                const auto It = Streams_.find(StreamId);
                if (StreamId < 0 || It == Streams_.end() || !It->second)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ProtocolError});
                }
                std::vector<std::byte> Data;
                for (std::size_t Index = 0; Index < static_cast<std::size_t>(Count); ++Index)
                {
                    const auto *Begin = reinterpret_cast<const std::byte *>(Vectors[Index].base);
                    Data.insert(Data.end(), Begin, Begin + Vectors[Index].len);
                }
                std::size_t Offset = 0;
                while (Offset < Data.size())
                {
                    std::error_code Error;
                    const auto Written = co_await It->second->Write(
                        std::span<const std::byte>(Data).subspan(Offset), Error);
                    if (Closed_)
                    {
                        co_return std::unexpected(
                            CurrentFailure(Fault::Code::Canceled));
                    }
                    if (Error)
                    {
                        co_return std::unexpected(Prism::Fault::FromNative(Error));
                    }
                    if (Written == 0 || Written > Data.size() - Offset)
                    {
                        co_return std::unexpected(
                            Prism::Fault::Failure{Fault::Code::IoError});
                    }
                    Offset += Written;
                    if (nghttp3_conn_add_write_offset(Conn_, StreamId, Written) != 0)
                    {
                        co_return std::unexpected(
                            Prism::Fault::Failure{Fault::Code::ProtocolError});
                    }
                }
                if (Fin != 0)
                {
                    nghttp3_conn_shutdown_stream_write(Conn_, StreamId);
                    const auto Shutdown = co_await It->second->ShutdownWrite();
                    if (Closed_)
                    {
                        co_return std::unexpected(
                            CurrentFailure(Fault::Code::Canceled));
                    }
                    if (!Shutdown)
                    {
                        co_return std::unexpected(Shutdown.error());
                    }
                }
            }
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }

} // namespace Prism::Http3::Detail
