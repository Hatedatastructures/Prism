/**
 * @file UdpAssocRetirement.hpp
 * @brief SOCKS5 UDP 关联的唯一关闭、失败保留与真实退栈 owner。
 * @details Run/Bind 操作、UDP socket、TCP Conn 全层 Activity 和 retry 实物共用此生命周期。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Protocols/Socks5/Conn.hpp>
#include <Prism/Transport/Reliable.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>
#include <cstddef>

namespace Prism::Socks5
{
    namespace Net = boost::asio;

    /**
     * @brief 管理一个 UDP_ASSOCIATE 的 Run、控制 TCP、原生 UDP socket 与失败退休。
     * @details Close/Cancel 只投递原 executor 请求；Drain 才观察 close 与所有层 I/O 的真实结果。
     */
    class UdpAssocRetirement final : public Prism::Contract::CarrierActivity,
                                     public Prism::Executor::ClosingResource,
                                     public std::enable_shared_from_this<UdpAssocRetirement>
    {
        friend class UdpAssoc;
        friend class UdpAssocBindGate;

    private:
        struct DrainWaiter final
        {
            explicit DrainWaiter(std::atomic<std::size_t> &Count);
            ~DrainWaiter();
            std::atomic<std::size_t> &Count_;
        };

    public:
        using Failure = Prism::Fault::Failure;
        using Result = std::expected<void, Failure>;
        using Completion = std::function<void()>;
        using Socket = Net::ip::udp::socket;

        struct ControlEndpointSnapshot final
        {
            Net::ip::tcp::endpoint Local;
            Net::ip::tcp::endpoint Peer;
        };

        /**
         * @brief 固定 TCP/UDP 管理 executor，并快照 TCP 所有层的真实 Activity owner。
         * @param Executor UDP 关联的原 executor；所有 UDP socket 与最终关闭都在此域执行。
         * @param Tcp 已接管的控制连接；本 owner 保留每层 Activity 直到 Drain 完成。
         */
        UdpAssocRetirement(Net::any_io_executor Executor,
                           std::shared_ptr<Conn<>> Tcp);

    private:
        class Operation final
        {
        public:
            Operation(Operation &&Other) noexcept;
            Operation(const Operation &) = delete;
            auto operator=(const Operation &) -> Operation & = delete;
            ~Operation();

            /** @brief 所有嵌套协程与 native completion 已退出，归还一次操作预约。 */
            auto Complete() noexcept -> void;

        private:
            friend class UdpAssocRetirement;
            Operation(std::shared_ptr<UdpAssocRetirement> Owner,
                      Prism::Protocols::ProtocolActivity::Reservation Reservation);

            std::shared_ptr<UdpAssocRetirement> Owner_;
            std::optional<Prism::Protocols::ProtocolActivity::Reservation> Reservation_;
        };

        [[nodiscard]] auto BeginOperation() -> std::expected<Operation, Failure>;

        [[nodiscard]] auto BeginRun() -> std::expected<Operation, Failure>;

    public:
        /** @brief 返回唯一 UDP 管理执行域；TCP 各层通过独立 Activity 保留其真实 executor。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override;

        /** @brief 封止新 Run/Bind 准入，不提前归还当前协程的操作预约。 */
        auto Seal() noexcept -> void override;

        /** @brief 请求关闭并等待 TCP 全层与关联操作退栈；保留并交付 Native 失败。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<Result> override;

    private:
        /** @brief Run 无首错时等待退休；已有首错则先返回，由公开 Drain 等待退休并交付错误。 */
        [[nodiscard]] auto RunDrain() -> Net::awaitable<Result>;

        [[nodiscard]] auto Ingress() noexcept -> Socket & { return Ingress_; }
        [[nodiscard]] auto Egress() noexcept -> Socket & { return Egress_; }
        [[nodiscard]] auto EgressProtocol() const noexcept
            -> std::optional<Net::ip::udp>
        {
            return EgressProtocol_;
        }
        auto SetEgressProtocol(Net::ip::udp Protocol) noexcept -> void;
        [[nodiscard]] auto Tcp() const noexcept -> std::shared_ptr<Conn<>> { return Tcp_; }
        [[nodiscard]] auto ReadControlEndpoints() const
            -> std::expected<ControlEndpointSnapshot, Failure>;
        auto CloseEgress() noexcept -> Failure;
        [[nodiscard]] auto CancellationSlot() noexcept -> Net::cancellation_slot
        { return Cancellation_.slot(); }
        [[nodiscard]] auto IsCancelled() const noexcept -> bool
        { return Cancelled_.load(std::memory_order_acquire); }
        [[nodiscard]] auto IsCloseRequested() const noexcept -> bool
        { return CloseRequested_.load(std::memory_order_acquire); }

        /** @brief 保留报告状态 owner；不封止操作、不发起关闭。 */
        auto PinOwner(std::shared_ptr<void> OwnerPin, Completion Callback) noexcept -> void;

        /** @brief 可跨线程调用；只登记 owner 并经原 executor 请求真实关闭。 */
        auto RequestClose(std::shared_ptr<void> OwnerPin = {}, Completion Callback = {}) noexcept -> void;

        /** @brief 可跨线程标记取消，并走同一个原 executor 幂等关闭路径。 */
        auto RequestCancel(std::shared_ptr<void> OwnerPin = {}, Completion Callback = {}) noexcept -> void;

        /** @brief 记录首个无法退休的真实错误并保留完整 association owner。 */
        auto RecordFailure(const Failure Value) noexcept -> void;

        auto RecordNative(const boost::system::error_code Native) noexcept -> void;

        /** @brief 保留异常的首次 owner failure，并返回该次精确 Code/Native 投影。 */
        [[nodiscard]] auto RecordException(const std::exception_ptr Exception) noexcept -> Failure;

        [[nodiscard]] auto LoadFailure() const noexcept -> Failure;

        auto RequestRetirement() -> void override;

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;

    private:
        struct Delivery final
        {
            std::shared_ptr<UdpAssocRetirement> Owner;
            bool Invoked{false};

            explicit Delivery(std::shared_ptr<UdpAssocRetirement> Value);
            Delivery(Delivery &&Other) noexcept;
            ~Delivery();
            auto operator()() -> void;
        };

        auto ScheduleRetirement() noexcept -> void;

        auto StartRetirement() noexcept -> void;

        [[nodiscard]] auto RetireOnExecutor() -> Net::awaitable<Result>;

        auto CompleteRetirement(std::exception_ptr Exception, Result RetiredResult) noexcept -> void;

        [[nodiscard]] static auto CloseSocket(Socket &Value) noexcept -> Failure;

        static auto PreserveFailure(Failure &Primary, const Failure &Next) noexcept -> void;

        auto Notify() noexcept -> void;

        [[nodiscard]] auto LoadCompletion() const noexcept -> Completion
        {
            const auto Value = Callback_.load(std::memory_order_acquire);
            return Value ? *Value : Completion{};
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        Prism::Protocols::ProtocolActivity Operations_;
        Net::experimental::concurrent_channel<void(boost::system::error_code)> Changes_;
        Net::ip::udp::socket Ingress_;
        Net::ip::udp::socket Egress_;
        std::optional<Net::ip::udp> EgressProtocol_;
        std::shared_ptr<Conn<>> Tcp_;
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>> TcpActivities_;
        Net::cancellation_signal Cancellation_;
        Prism::Fault::FailureState FailureState_;
        std::atomic<std::shared_ptr<const std::error_code>> NativeFailure_;
        std::atomic<std::shared_ptr<void>> OwnerPin_;
        std::atomic<std::shared_ptr<Completion>> Callback_;
        std::atomic<bool> RunStarted_{false};
        std::atomic<bool> CloseRequested_{false};
        std::atomic<bool> Cancelled_{false};
        std::atomic<bool> Scheduled_{false};
        std::atomic<bool> Retired_{false};
        std::atomic<bool> FailureObserved_{false};
        std::atomic<std::size_t> DrainWaiters_{0};

        [[nodiscard]] static auto FailureFromException(
            const std::exception_ptr Exception) noexcept -> Failure;

        [[nodiscard]] auto AwaitRetirement(const bool ConsumeFailure)
            -> Net::awaitable<Result>;

        [[nodiscard]] auto CompletedResult(const bool ConsumeFailure) noexcept -> Result;

        auto WakeWaiter() noexcept -> void;
    };
}
