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
#include <Prism/Protocols/Http3/NativeClient.hpp>
#include <Prism/Protocols/Http3/Detail/BoundedEventQueue.hpp>
#include <Prism/Protocols/Http3/Detail/NativeClientCallbackApi.hpp>
#include <Prism/Protocols/Http3/Detail/TrackedSessionTasks.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http3::Detail
{

    namespace Net = boost::asio;

    struct Http3ReadLoopTestAccess;

    class NativeClientSessionOwner final : public std::enable_shared_from_this<NativeClientSessionOwner>
    {
    public:
        explicit NativeClientSessionOwner(Prism::Http3::NativeClientSessionOptions Options);
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
        friend struct Http3ReadLoopTestAccess;
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

        [[nodiscard]] auto SpawnAcceptLoop() -> bool;

        [[nodiscard]] auto SpawnReadLoop(Prism::Quic::SharedStreamProvider Provider) -> bool;

        auto OnTrackedTaskComplete(std::exception_ptr Exception) noexcept -> void;

        auto OnTrackedTaskStartFailure(std::exception_ptr Exception) noexcept -> void;

        auto RecordFailure(Prism::Fault::Failure Failure) noexcept -> void;

        [[nodiscard]] auto CurrentFailure(const Fault::Code Code) const noexcept
            -> Prism::Fault::Failure
        {
            if (FirstFailure_.Failed()) return FirstFailure_;
            return Prism::Fault::Failure{Code};
        }

        auto TrackPendingProvider(
            const Prism::Quic::SharedStreamProvider &Provider) -> void;

        auto ForgetPendingProvider(
            const Prism::Quic::SharedStreamProvider &Provider) -> void;

        [[nodiscard]] auto EnsureReady()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto OpenInitialStreams()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto InitializeHttp3() -> bool;

        [[nodiscard]] auto SubmitRequest() -> bool;

        [[nodiscard]] auto AcceptLoop() -> Net::awaitable<void>;

        [[nodiscard]] auto ReadLoop(
            const Prism::Quic::SharedStreamProvider &Provider) -> Net::awaitable<void>;

        [[nodiscard]] auto Publish(std::shared_ptr<Event> Event) -> bool;

        auto PruneClosedStreams() -> void;

        [[nodiscard]] auto HandleEvent(Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto DrainOutput()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

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
