/**
 * @file NativeClient.hpp
 * @brief 原生 QUIC 连接上的 HTTP/3 客户端适配器。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nghttp3/nghttp3.h>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Protocols/Http3/Server.hpp>
#include <Prism/Protocols/Http3/HeaderLimits.hpp>
#include <Prism/Protocols/Http3/Detail/BoundedEventQueue.hpp>
#include <Prism/Protocols/Http3/Detail/NativeClientCallbackApi.hpp>
#include <Prism/Protocols/Http3/Detail/TrackedSessionTasks.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http3::Detail
{

    namespace Net = boost::asio;

    class NativeClientSessionOwner final : public std::enable_shared_from_this<NativeClientSessionOwner>
    {
    public:
        explicit NativeClientSessionOwner(Prism::Http3::NativeClientSessionOptions Options)
            : Options_(std::move(Options)),
              Events_(std::make_unique<BoundedEventQueue<Event>>(Options_.Executor)),
              Tasks_(Options_.Executor)
        {
            PendingProviders_.reserve(HeaderLimits::MaxPendingEvents + 1U);
        }
        NativeClientSessionOwner(const NativeClientSessionOwner &) = delete;
        auto operator=(const NativeClientSessionOwner &) -> NativeClientSessionOwner & = delete;

        [[nodiscard]] auto SendRequest(RequestHead Request)
            -> Net::awaitable<std::expected<ResponseHead, Prism::Fault::Failure>>;

        [[nodiscard]] auto OpenBidirectionalStream()
            -> Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                            Prism::Fault::Failure>>;

        /** @brief 请求在原 executor 上关闭；成功只表示命令已接管。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult;

        [[nodiscard]] auto HandshakeReady() const noexcept -> bool
        {
            return Options_.Connection && Options_.Connection->Health().HandshakeReady;
        }

        [[nodiscard]] auto ProtocolReady() const noexcept -> bool
        {
            return Ready_ && !Closed_;
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto IsRetired() const noexcept -> bool;

    private:
        [[nodiscard]] auto SendRequestCore(RequestHead Request)
            -> Net::awaitable<std::expected<ResponseHead, Prism::Fault::Failure>>;
        [[nodiscard]] auto OpenBidirectionalStreamCore()
            -> Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                            Prism::Fault::Failure>>;
        [[nodiscard]] auto ReceiveResponse()
            -> Net::awaitable<std::expected<ResponseHead, Prism::Fault::Failure>>;

        [[nodiscard]] auto DrainProvider(
            const Prism::Quic::SharedStreamProvider &Provider)
            -> Net::awaitable<bool>;

        struct TaskReservation final
        {
            explicit TaskReservation(TrackedSessionTasks<NativeClientSessionOwner> &Value) noexcept
                : Tasks(Value) {}
            ~TaskReservation() { Tasks.Leave(); }
            TrackedSessionTasks<NativeClientSessionOwner> &Tasks;
        };

        struct RequestReservation final
        {
            explicit RequestReservation(bool &Value) noexcept : Active(Value)
            {
                Active = true;
            }
            ~RequestReservation() { Active = false; }
            bool &Active;
        };

        friend struct NativeClientCallbacks;
        template <class Owner>
        friend class TrackedSessionTasks;

        enum class EventType : std::uint8_t
        {
            NewStream,
            Data,
            Error,
        };

        struct Event final
        {
            EventType Type{EventType::Error};
            bool Fin{false};
            bool BudgetReserved{false};
            std::size_t BudgetBytes{0};
            std::error_code Error{};
            Prism::Quic::SharedStreamProvider Provider{};
            std::vector<std::byte> Data;
        };

        using EventQueue = BoundedEventQueue<Event>;

        [[nodiscard]] auto SpawnAcceptLoop() -> bool
        {
            const auto Self = shared_from_this();
            auto Work = [Self]() -> Net::awaitable<void> { co_await Self->AcceptLoop(); };
            return Tasks_.Spawn(Options_.Executor, Self, std::move(Work));
        }

        [[nodiscard]] auto SpawnReadLoop(Prism::Quic::SharedStreamProvider Provider) -> bool
        {
            const auto Self = shared_from_this();
            auto Work = [Self, Provider = std::move(Provider)]() -> Net::awaitable<void>
            {
                co_await Self->ReadLoop(Provider);
            };
            return Tasks_.Spawn(Options_.Executor, Self, std::move(Work));
        }

        auto OnTrackedTaskComplete(std::exception_ptr Exception) noexcept -> void
        {
            if (Exception)
            {
                TaskFailed_.store(true, std::memory_order_release);
                RecordFailure(
                    Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::move(Exception)));
                CloseOnExecutor();
            }
        }

        auto OnTrackedTaskStartFailure(std::exception_ptr Exception) noexcept -> void
        {
            TaskFailed_.store(true, std::memory_order_release);
            RecordFailure(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception)));
            CloseOnExecutor();
        }

        auto RecordFailure(Prism::Fault::Failure Failure) noexcept -> void
        {
            if (!FirstFailure_.Failed() && Failure.Failed()) FirstFailure_ = Failure;
        }

        [[nodiscard]] auto CurrentFailure(const Fault::Code Code) const noexcept
            -> Prism::Fault::Failure
        {
            if (FirstFailure_.Failed()) return FirstFailure_;
            return Prism::Fault::Failure{Code};
        }

        auto TrackPendingProvider(
            const Prism::Quic::SharedStreamProvider &Provider) -> void
        {
            if (std::find(PendingProviders_.begin(),
                          PendingProviders_.end(), Provider) !=
                PendingProviders_.end())
            {
                return;
            }
            PendingProviders_.push_back(Provider);
        }

        auto ForgetPendingProvider(
            const Prism::Quic::SharedStreamProvider &Provider) -> void
        {
            const auto Pending = std::find(
                PendingProviders_.begin(), PendingProviders_.end(), Provider);
            if (Pending != PendingProviders_.end()) PendingProviders_.erase(Pending);
        }

        [[nodiscard]] auto EnsureReady()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto OpenInitialStreams()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto InitializeHttp3() -> bool
        {
            return NativeClientCallbacks::Initialize(*this);
        }

        [[nodiscard]] auto SubmitRequest() -> bool
        {
            return NativeClientCallbacks::Submit(*this);
        }

        [[nodiscard]] auto AcceptLoop() -> Net::awaitable<void>
        {
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

        [[nodiscard]] auto ReadLoop(
            const Prism::Quic::SharedStreamProvider &Provider) -> Net::awaitable<void>
        {
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
                if (Error)
                {
                    PendingEvent->Type = EventType::Error;
                    PendingEvent->Error = Error;
                    RecordFailure(Prism::Fault::FromNative(Error));
                    const auto Published = Publish(std::move(PendingEvent));
                    if (!Published)
                    {
                        RecordFailure({Fault::Code::ResourceUnavailable});
                    }
                    CloseOnExecutor();
                    co_return;
                }
                if (Count > Buffer.size())
                {
                    RecordFailure({Fault::Code::ProtocolError});
                    CloseOnExecutor();
                    co_return;
                }
                PendingEvent->Type = EventType::Data;
                PendingEvent->Fin = Count == 0;
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
                if (Count == 0) co_return;
            }
        }

        [[nodiscard]] auto Publish(std::shared_ptr<Event> Event) -> bool
        {
            return !Closed_ && Events_ && Events_->Publish(std::move(Event));
        }

        auto PruneClosedStreams() -> void
        {
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

        [[nodiscard]] auto HandleEvent(Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
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

        [[nodiscard]] auto DrainOutput()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
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

        auto CloseOnExecutor() -> void;
        auto RetireOnExecutor() noexcept -> void;

        Prism::Http3::NativeClientSessionOptions Options_;
        std::unique_ptr<EventQueue> Events_;
        TrackedSessionTasks<NativeClientSessionOwner> Tasks_;
        nghttp3_conn *Conn_{nullptr};
        std::array<Prism::Quic::SharedStreamProvider, 3> Http3Streams_{};
        std::unordered_map<std::int64_t, Prism::Quic::SharedStreamProvider> Streams_;
        std::vector<Prism::Quic::SharedStreamProvider> PendingProviders_;
        Prism::Quic::SharedStreamProvider RequestStream_{};
        std::int64_t RequestStreamId_{-1};
        std::int64_t ResponseStreamId_{-1};
        std::optional<HeaderBlock> RequestHeaders_;
        HeaderBlock ResponseHeaders_{std::make_shared<Prism::Memory::SessionResource<>>()};
        std::uint16_t ResponseStatus_{0};
        bool RequestFin_{false};
        bool RandomFailed_{false};
        bool Ready_{false};
        bool RequestActive_{false};
        bool ResponseHeadersDone_{false};
        bool ResponseDone_{false};
        bool ResponseFin_{false};
        bool Closed_{false};
        std::atomic<bool> ClosedAtomic_{false};
        std::atomic<bool> NativeEngineRetiredAtomic_{false};
        std::atomic<bool> EventQueueRetiredAtomic_{false};
        std::atomic<bool> RetiredAtomic_{false};
        std::atomic<bool> TaskFailed_{false};
        Prism::Fault::Failure FirstFailure_{};
    };

} // namespace Prism::Http3::Detail


#include <Prism/Protocols/Http3/Detail/NativeClientCallbacks.hpp>
#include <Prism/Protocols/Http3/Detail/NativeClientLifecycle.hpp>
#include <Prism/Protocols/Http3/Detail/NativeClientRequests.hpp>
