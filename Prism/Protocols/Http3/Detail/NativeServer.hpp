/**
 * @file NativeServer.hpp
 * @brief QUIC 流提供者上的 HTTP/3 通用会话适配器。
 * @details Native QUIC 持有 socket 与连接关闭责任；本类持有
 * HTTP/3 控制流、每流读取任务和类型化事件分发。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Http3/NativeServer.hpp>
#include <Prism/Protocols/Http3/Server.hpp>
#include <Prism/Protocols/Http3/ServerFactory.hpp>
#include <Prism/Protocols/Http3/Detail/BoundedEventQueue.hpp>
#include <Prism/Protocols/Http3/Detail/TrackedSessionTasks.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Protocols/Http3/HeaderLimits.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http3::Detail
{

    namespace Net = boost::asio;

    class NativeServerSessionOwner;

    struct NativeServerOutputDriver final
    {
        [[nodiscard]] static auto Drain(NativeServerSessionOwner &Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };

    class NativeServerSessionOwner final : public std::enable_shared_from_this<NativeServerSessionOwner>
    {
    public:
        explicit NativeServerSessionOwner(NativeServerSessionOptions Options)
            : Options_(std::move(Options)),
              Server_(CreateServer(Options_)),
              Events_(std::make_unique<EventQueue>(Options_.Executor)),
              Tasks_(Options_.Executor)
        {
            PendingProviders_.reserve(HeaderLimits::MaxPendingEvents + 2U);
        }

        NativeServerSessionOwner(const NativeServerSessionOwner &) = delete;
        auto operator=(const NativeServerSessionOwner &) -> NativeServerSessionOwner & = delete;

        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 请求在原 executor 上关闭；成功只表示命令已接管。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult;

        /** @brief 原 executor 关闭 HTTP3 children，等待 Run、accept/read 实际退栈，无固定延迟。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto ProtocolReady() const noexcept -> bool;

        /** @brief 只读取本会话的实际关闭、任务退栈和 HTTP/3 engine 释放状态。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

    private:
        [[nodiscard]] auto RunCore()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 仅在 factory 存在时创建拥有型 HTTP/3 server。 */
        [[nodiscard]] static auto CreateServer(
            const Prism::Http3::NativeServerSessionOptions &Options)
            -> Prism::Http3::SharedServer
        {
            if (!Options.Factory)
            {
                return nullptr;
            }
            return Options.Factory->Create(Options.Http);
        }

        friend struct NativeServerOutputDriver;

        struct TaskReservation final
        {
            explicit TaskReservation(TrackedSessionTasks<NativeServerSessionOwner> &Value) noexcept
                : Tasks(Value) {}
            ~TaskReservation() { Tasks.Leave(); }
            TrackedSessionTasks<NativeServerSessionOwner> &Tasks;
        };

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
            bool Unidirectional{false};
            bool Fin{false};
            bool BudgetReserved{false};
            std::size_t BudgetBytes{0};
            std::error_code Error{};
            Prism::Quic::SharedStreamProvider Provider{};
            std::vector<std::byte> Data;
        };

        using EventQueue = BoundedEventQueue<Event>;

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

        auto CloseOnExecutor() -> void;
        auto RecordFailure(Prism::Fault::Failure Failure) noexcept -> void;
        [[nodiscard]] auto DrainProvider(
            const Prism::Quic::SharedStreamProvider &Provider)
            -> Net::awaitable<bool>;

        [[nodiscard]] auto OpenHttp3Streams()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
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

        [[nodiscard]] auto InitializeHttp3() -> bool
        {
            std::size_t Index = 0;
            return Server_->Init([this, Index]() mutable -> std::int64_t {
                if (Index >= Http3Streams_.size() || !Http3Streams_[Index])
                {
                    return -1;
                }
                return Http3Streams_[Index++]->StreamId();
            });
        }

        [[nodiscard]] auto SpawnAcceptLoop(const bool Unidirectional) -> bool
        {
            const auto Self = shared_from_this();
            auto Work = [Self, Unidirectional]() -> Net::awaitable<void>
            {
                co_await Self->AcceptLoop(Unidirectional);
            };
            return Tasks_.Spawn(Options_.Executor, Self, std::move(Work));
        }

        [[nodiscard]] auto SpawnReadLoop(
            Prism::Quic::SharedStreamProvider Provider,
            const bool Unidirectional) -> bool
        {
            const auto Self = shared_from_this();
            auto Work = [Self, Provider = std::move(Provider), Unidirectional]() -> Net::awaitable<void>
            {
                co_await Self->ReadLoop(Provider, Unidirectional);
            };
            return Tasks_.Spawn(Options_.Executor, Self, std::move(Work));
        }

        [[nodiscard]] auto AcceptLoop(const bool Unidirectional) -> Net::awaitable<void>
        {
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

        [[nodiscard]] auto ReadLoop(
            const Prism::Quic::SharedStreamProvider &Provider,
            const bool Unidirectional) -> Net::awaitable<void>
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
                PendingEvent->Unidirectional = Unidirectional;
                if (Error)
                {
                    Observe(NativeServerSessionStage::Error,
                            Fault::Code::IoError, Provider->StreamId());
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
                Observe(NativeServerSessionStage::DataEvent,
                        Fault::Code::Success, Provider->StreamId());
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
            if (!Events_ || !Event)
            {
                return false;
            }
            return Events_->Publish(std::move(Event));
        }

        [[nodiscard]] auto HandleEvent(Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            EventQueue::Reservation Reservation(*Events_, Event);
            if (Event.Type == EventType::NewStream)
            {
                co_return co_await HandleNewStream(Event);
            }
            if (Event.Type == EventType::Error || !Event.Provider)
            {
                auto Failure = Prism::Fault::Failure{Fault::Code::IoError};
                if (Event.Error) Failure = Prism::Fault::FromNative(Event.Error);
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

        auto PruneClosedStreams() -> void
        {
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

        [[nodiscard]] auto HasStreamCapacity() const noexcept -> bool
        {
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

        [[nodiscard]] auto HandleNewStream(const Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
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

        [[nodiscard]] auto Dispatch(ServerEvent Event) -> Net::awaitable<SessionAction>
        {
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

        Prism::Http3::NativeServerSessionOptions Options_;
        std::shared_ptr<Server> Server_;
        std::unique_ptr<EventQueue> Events_;
        TrackedSessionTasks<NativeServerSessionOwner> Tasks_;
        std::array<Prism::Quic::SharedStreamProvider, 3> Http3Streams_{};
        std::unordered_map<std::int64_t, Prism::Quic::SharedStreamProvider> Streams_;
        std::vector<Prism::Quic::SharedStreamProvider> PendingProviders_;
        std::unordered_map<std::int64_t, StreamMode> Modes_;
        bool Closed_{false};
        std::atomic<bool> ClosedAtomic_{false};
        std::atomic<bool> TaskFailed_{false};
        std::atomic<bool> EventQueueRetiredAtomic_{false};
        std::atomic<bool> RetiredAtomic_{false};
        Prism::Fault::Failure FirstFailure_{};

        auto Observe(const NativeServerSessionStage Stage,
                     const Fault::Code Status = Fault::Code::Success,
                     const std::int64_t StreamId = -1) noexcept -> void
        {
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
    };

} // namespace Prism::Http3::Detail

#include <Prism/Protocols/Http3/Detail/NativeServerOutputDriver.hpp>
#include <Prism/Protocols/Http3/Detail/NativeServerRun.hpp>
#include <Prism/Protocols/Http3/Detail/NativeServerLifecycle.hpp>
