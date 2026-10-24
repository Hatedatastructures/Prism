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
#include <Prism/Protocols/Http3/Detail/BoundedEventQueue.hpp>
#include <Prism/Protocols/Http3/Detail/TrackedSessionTasks.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Protocols/Http3/HeaderLimits.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http3::Detail
{

    namespace Net = boost::asio;

    class NativeServerSessionOwner;
    struct Http3ReadLoopTestAccess;

    struct NativeServerOutputDriver final
    {
        [[nodiscard]] static auto Drain(NativeServerSessionOwner &Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };

    class NativeServerSessionOwner final : public std::enable_shared_from_this<NativeServerSessionOwner>
    {
    public:
        explicit NativeServerSessionOwner(NativeServerSessionOptions Options);

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
            -> Prism::Http3::SharedServer;

        friend struct NativeServerOutputDriver;
        friend struct Http3ReadLoopTestAccess;

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

        auto OnTrackedTaskComplete(std::exception_ptr Exception) noexcept -> void;

        auto OnTrackedTaskStartFailure(std::exception_ptr Exception) noexcept -> void;

        auto CloseOnExecutor() -> void;
        auto RecordFailure(Prism::Fault::Failure Failure) noexcept -> void;
        [[nodiscard]] auto DrainProvider(
            const Prism::Quic::SharedStreamProvider &Provider)
            -> Net::awaitable<bool>;

        [[nodiscard]] auto OpenHttp3Streams()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto InitializeHttp3() -> bool;

        [[nodiscard]] auto SpawnAcceptLoop(const bool Unidirectional) -> bool;

        [[nodiscard]] auto SpawnReadLoop(
            Prism::Quic::SharedStreamProvider Provider,
            const bool Unidirectional) -> bool;

        [[nodiscard]] auto AcceptLoop(const bool Unidirectional) -> Net::awaitable<void>;

        [[nodiscard]] auto ReadLoop(
            const Prism::Quic::SharedStreamProvider &Provider,
            const bool Unidirectional) -> Net::awaitable<void>;

        [[nodiscard]] auto Publish(std::shared_ptr<Event> Event) -> bool;

        [[nodiscard]] auto HandleEvent(Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        auto PruneClosedStreams() -> void;

        [[nodiscard]] auto HasStreamCapacity() const noexcept -> bool;

        [[nodiscard]] auto HandleNewStream(const Event &Event)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto Dispatch(ServerEvent Event) -> Net::awaitable<SessionAction>;

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
                     const std::int64_t StreamId = -1) noexcept -> void;
    };

} // namespace Prism::Http3::Detail
