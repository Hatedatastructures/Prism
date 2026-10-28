/**
 * @file CarrierOwner.hpp
 * @brief TrustTunnel HTTP/2 carrier 生命周期、关闭与真实物理排空。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/WireWriter.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Trusttunnel
{
    struct WireAuthBinding;
    class AuthenticatedTransport;
}

namespace Prism::Trusttunnel::Detail
{
    namespace Net = boost::asio;

    struct Http2DriverParameters;
    using CarrierClosedChannel =
        Net::experimental::channel<void(boost::system::error_code)>;
    using CarrierDrainGate =
        Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    /**
     * @struct CarrierLifecycle
     * @brief TrustTunnel carrier driver 的完成通知与弱观察句柄。
     * @details DriverState 由 HTTP/2 driver owning frame 持有；driver 清理 callback、
     *          取消 raw read 并由 co_spawn completion 释放后，Closed 才通知观察者。
     */
    struct CarrierLifecycle final
    {
        explicit CarrierLifecycle(Net::any_io_executor Executor);

        std::shared_ptr<CarrierClosedChannel> Closed;
        std::shared_ptr<CarrierDrainGate> DrainGate;
        std::weak_ptr<const Http2DriverParameters> DriverState;
        /** @brief 双方 END_STREAM 完成后的物理拆除窗口。 */
        std::weak_ptr<Http2Transport> Transport;
        Prism::Fault::FailureState FirstFailure;
        std::atomic<bool> DriverStarted{false};
        std::atomic<bool> DriverCompleted{false};
        /** @brief 本端已发起 clean Close；只用于抑制由该动作取消挂起读取产生的 Canceled。 */
        std::atomic<bool> Closing{false};
        std::atomic<bool> LayersDrained{false};
        std::atomic<bool> TransportDrained{false};
        std::atomic<bool> WireDrained{false};
        std::atomic<bool> EncryptedDrained{false};
        std::atomic<bool> TransportActivityRetired{false};
        std::atomic<bool> TransportOpen{true};
        std::atomic<bool> EncryptedActivityRetired{false};
        std::atomic<bool> EncryptedOpen{true};
        std::atomic<bool> Retired{false};

        auto RecordFailure(const Prism::Fault::Failure Value) noexcept -> void;

        /** @brief 判断失败是否属于连接拆除阶段的取消/中止，而非对端业务失败。 */
        [[nodiscard]] static auto IsTeardownFailure(
            const Prism::Fault::Failure Value) noexcept -> bool
        {
            if (Value.Code != Prism::Fault::Code::Eof &&
                Value.Code != Prism::Fault::Code::Canceled &&
                Value.Code != Prism::Fault::Code::ConnectionAborted &&
                Value.Code != Prism::Fault::Code::ConnectionReset &&
                Value.Code != Prism::Fault::Code::IoError)
                return false;
            if (!Value.Native)
                return Value.Code != Prism::Fault::Code::IoError;
            // 调用方已确认双向 END_STREAM，TLS 缺失 close_notify 不再截断 HTTP/2 业务数据。
            if (Value.Native == static_cast<std::error_code>(
                    Net::ssl::error::make_error_code(
                        Net::ssl::error::stream_truncated)))
                return true;
#ifdef _WIN32
            // Windows 的 native socket 关闭竞态可能落在 system category：
            // 995=ERROR_OPERATION_ABORTED, 1236=ERROR_CONNECTION_ABORTED,
            // 10054=WSAECONNRESET, 10053=WSAECONNABORTED。
            switch (Value.Native.value())
            {
            case 995:
            case 1236:
            case 10053:
            case 10054:
                return true;
            default:
                break;
            }
#endif
            return Value.Native ==
                       static_cast<std::error_code>(
                           Net::error::make_error_code(Net::error::operation_aborted)) ||
                Value.Native ==
                       static_cast<std::error_code>(
                           Net::error::make_error_code(Net::error::connection_aborted)) ||
                Value.Native ==
                       static_cast<std::error_code>(
                           Net::error::make_error_code(Net::error::connection_reset)) ||
                Value.Native ==
                       static_cast<std::error_code>(
                           Net::error::make_error_code(Net::error::eof)) ||
                Value.Native == std::make_error_code(std::errc::operation_canceled) ||
                Value.Native == std::make_error_code(std::errc::connection_aborted) ||
                Value.Native == std::make_error_code(std::errc::connection_reset);
        }

        /** @brief 判断失败是否仅由本端 clean Close 唤醒挂起读取而产生。 */
        [[nodiscard]] auto IsLocalCloseCancellation(
            const Prism::Fault::Failure Value) const noexcept -> bool
        {
            if (!Closing.load(std::memory_order_acquire)) return false;
            return IsTeardownFailure(Value);
        }

        [[nodiscard]] auto Failure() const noexcept -> Prism::Fault::Failure
        {
            return FirstFailure.Load();
        }

        auto StartDriver() noexcept -> void;

        auto CompleteDriver() noexcept -> void;

        [[nodiscard]] auto WaitDriver()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };

    /**
     * @struct CarrierOwner
     * @brief 持有 HTTP/2 stream、wire writer 和 TLS raw read 的正式关闭 owner。
     * @details Close/Cancel 会取消并关闭底层 TLS，Shutdown 只提交 END_STREAM，
     *          保留反向读取能力。generation Binding pin 保留到 stream、writer、driver
     *          与 TLS 都确认物理退休后释放。
     */
    /** @brief TrustTunnel H2 最终关闭者的实际 stream、writer、TLS 与 driver 层。 */
    struct CarrierOwnerLayers final
    {
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        /** @brief accepted generation pin；仅 Retire 在完整物理退休后释放。 */
        std::shared_ptr<const Prism::Trusttunnel::WireAuthBinding> Binding;
    };

    struct CarrierOwner final : Prism::Executor::ClosingResource,
                                std::enable_shared_from_this<CarrierOwner>
    {
        explicit CarrierOwner(CarrierOwnerLayers Layers);

        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        /** @brief generation pin；仅 Retire 在完整物理退休后释放。 */
        std::shared_ptr<const Prism::Trusttunnel::WireAuthBinding> Binding;

        struct RetryCommand final
        {
            std::shared_ptr<CarrierOwner> Owner;
            auto operator()() noexcept -> void;
        };

        struct RetryCompletion final
        {
            std::shared_ptr<CarrierOwner> Owner;

            auto operator()(
                std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Result) const noexcept -> void;
        };

        /** @brief 返回冷构造时绑定的实际载体执行域；空载体由装配层拒绝。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            if (Transport) return Transport->Executor();
            if (Encrypted) return Encrypted->Executor();
            return Lifecycle->Closed->get_executor();
        }

        /** @brief 读取 driver、writer、TLS 与 H2 stream 全部物理退栈的事实。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Lifecycle && Lifecycle->Retired.load(std::memory_order_acquire);
        }

        /** @brief 关闭 HTTP/2 stream、wire writer 与底层加密载体；首个真实失败被保留。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult;

        /** @brief 可重复取消；成功只表示命令已接管，不宣称底层已经关闭。 */
        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult;

        /** @brief 重试关闭并等待 driver、frame writer 与加密载体的真实活动排空。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        auto RequestRetirement() -> void override;

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !Reclaimer_ || !Reclaimer_->CanDispatch();
        }

        /** @brief 真实写半关闭：只提交 END_STREAM，保留反向读取能力。 */
        auto WriteShutdown(Prism::Transmission::Completion Handler) -> void;

    private:
        auto RecordControlFailure(const Prism::Transmission::ControlResult &Result) noexcept -> void;

        [[nodiscard]] auto DrainTransport() -> Net::awaitable<bool>;

        [[nodiscard]] auto DrainWire() -> Net::awaitable<bool>;

        [[nodiscard]] auto DrainEncrypted() -> Net::awaitable<bool>;

        friend class Prism::Trusttunnel::AuthenticatedTransport;

        /** @brief 释放物理层与 generation pin；仅在所有层都确认 IsRetired 后调用。 */
        auto Retire() noexcept -> void;

        [[nodiscard]] auto RetryOnExecutor()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        auto StartRetry() noexcept -> void;

        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        std::atomic<bool> RetryScheduled_{false};
    };


} // namespace Prism::Trusttunnel::Detail
