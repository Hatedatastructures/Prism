/**
 * @file UdpAssocBindGate.hpp
 * @brief SOCKS5 UDP_ASSOCIATE bind 与 BND wire 的唯一准入 owner。
 * @details 单次 bind/reply 与并发 Run 共用 typed 结果；每个等待调用保留独立取消和操作预约。
 */
#pragma once

#include <Prism/Protocols/Socks5/UdpAssocRetirement.hpp>
#include <Prism/Protocols/Socks5/Codec.hpp>
#include <Prism/Protocols/Socks5/Detail/UdpAddress.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/system_error.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Socks5
{
    namespace Net = boost::asio;

    /**
     * @class UdpAssocBindGate
     * @brief 拥有一次性 UDP bind、BND 回复和并发等待结果。
     * @details 状态只在关联 strand 上访问；退休 owner 持有本操作 reservation 与失败回执。
     */
    class UdpAssocBindGate final : public std::enable_shared_from_this<UdpAssocBindGate>
    {
    public:
        using Endpoint = Net::ip::udp::endpoint;
        using Result = ReplyResult<std::size_t>;

        /** @brief 在关联 executor 上创建并绑定唯一退休 owner。 */
        UdpAssocBindGate(Net::any_io_executor Executor,
                         std::shared_ptr<UdpAssocRetirement> Retirement)
            : Executor_(std::move(Executor)), Retirement_(std::move(Retirement))
        {
        }

        /**
         * @brief 执行或等待唯一的 bind 与 BND 回复。
         * @return 完整 wire 字节数或保留协议码、Native 与 partial progress 的失败。
         * @note 首个调用启动底层操作；取消等待者只结束自己的等待，不取消共享操作。
         */
        [[nodiscard]] auto Run() -> Net::awaitable<Result>
        {
            [[maybe_unused]] const auto Self = shared_from_this();
            co_await Net::dispatch(Executor_, Net::use_awaitable);
            if (Result_) co_return *Result_;

            auto Admission = Retirement_->BeginOperation();
            if (!Admission)
            {
                co_return FailureResult(Error::NotOpen, Admission.error(), 0);
            }
            [[maybe_unused]] auto Operation = std::move(*Admission);

            const auto Next = Enter();
            if (Next == Action::Completed) co_return *Result_;
            if (Next == Action::Wait) co_return co_await Wait();

            const auto Value = co_await BindAndReplyCore();
            co_await Net::dispatch(Executor_, Net::use_awaitable);
            Complete(Value);
            if (!Value)
            {
                if (Value.error().Transport.Failed())
                    Retirement_->RecordFailure(Value.error().Transport);
                Retirement_->RequestClose();
            }
            co_return Value;
        }

        /** @brief 返回 bind 成功后的本地 BND 端点。 */
        [[nodiscard]] auto LocalEndpoint() const -> Endpoint
        {
            if (BoundEndpoint_) return *BoundEndpoint_;
            return Retirement_->Ingress().local_endpoint();
        }

        /** @brief 返回已绑定时用于 SOCKS5 peer 检查的控制端点快照。 */
        [[nodiscard]] auto ControlPeer() const -> std::optional<Endpoint>
        {
            return ControlPeer_;
        }

    private:
        enum class Action
        {
            Start,
            Wait,
            Completed,
        };

        /** @brief 只由 strand 调用，选择唯一执行者或共享等待者。 */
        [[nodiscard]] auto Enter() noexcept -> Action
        {
            if (Result_) return Action::Completed;
            if (Running_) return Action::Wait;
            Running_ = true;
            return Action::Start;
        }

        /** @brief 等待首个调用发布结果；本 timer 仅属于当前 waiter。 */
        [[nodiscard]] auto Wait() -> Net::awaitable<Result>
        {
            std::shared_ptr<Net::steady_timer> Waiter;
            try
            {
                Waiter = std::make_shared<Net::steady_timer>(Executor_);
                Waiter->expires_at((Net::steady_timer::time_point::max)());
                Waiters_.erase(std::remove_if(Waiters_.begin(), Waiters_.end(),
                    [](const auto &Value) { return Value.expired(); }), Waiters_.end());
                Waiters_.push_back(Waiter);
            }
            catch (const boost::system::system_error &ErrorValue)
            {
                co_return FailureResult(Error::IoError,
                    Prism::Fault::FromNative(
                        static_cast<std::error_code>(ErrorValue.code())), 0);
            }
            catch (const std::system_error &ErrorValue)
            {
                co_return FailureResult(Error::IoError,
                    Prism::Fault::FromNative(ErrorValue.code()), 0);
            }
            catch (...)
            {
                co_return FailureResult(Error::IoError,
                    {Prism::Fault::Code::ResourceUnavailable}, 0);
            }

            boost::system::error_code ErrorCode;
            co_await Waiter->async_wait(
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (Result_) co_return *Result_;
            if (ErrorCode)
            {
                co_return FailureResult(Error::Canceled,
                    Prism::Fault::FromNative(static_cast<std::error_code>(ErrorCode)), 0);
            }
            co_return FailureResult(Error::IoError,
                {Prism::Fault::Code::Blocked}, 0);
        }

        /** @brief 绑定并记录 socket/native 失败；不发送第二份 BND wire。 */
        [[nodiscard]] auto BindSockets(const UdpAssocRetirement::ControlEndpointSnapshot &Control)
            -> ReplyResult<Endpoint>
        {
            const auto Protocol = Control.Local.address().is_v4()
                                      ? Net::ip::udp::v4()
                                      : Net::ip::udp::v6();
            auto &Ingress = Retirement_->Ingress();
            auto &Egress = Retirement_->Egress();
            boost::system::error_code ErrorCode;
            Ingress.open(Protocol, ErrorCode);
            if (ErrorCode) return std::unexpected(SocketFailure(ErrorCode));
            Egress.open(Protocol, ErrorCode);
            if (ErrorCode) return std::unexpected(SocketFailure(ErrorCode));
            Retirement_->SetEgressProtocol(Protocol);
            Ingress.bind(Endpoint(Control.Local.address(), 0), ErrorCode);
            if (ErrorCode) return std::unexpected(SocketFailure(ErrorCode));
            const auto Local = Ingress.local_endpoint(ErrorCode);
            if (ErrorCode) return std::unexpected(SocketFailure(ErrorCode));
            return Local;
        }

        /** @brief 把原生 socket 失败同时投递到 public Drain 与当前 bind 结果。 */
        [[nodiscard]] auto SocketFailure(const boost::system::error_code ErrorCode)
            -> ReplyFailure
        {
            const auto Cause = Prism::Fault::FromNative(
                static_cast<std::error_code>(ErrorCode));
            Retirement_->RecordFailure(Cause);
            return {Error::IoError, Cause, 0};
        }

        /** @brief setup 失败后尽力提交 GeneralFailure，并保留原始 typed/native cause。 */
        [[nodiscard]] auto SendGeneralFailure(
            const std::shared_ptr<Conn<>> &Tcp,
            ReplyFailure Failure) -> Net::awaitable<Result>
        {
            try
            {
                (void)co_await Tcp->SendAssocReply(ReplyCode::GeneralFailure, Address{});
            }
            catch (...)
            {
                // 错误回复写入异常不能覆盖导致 setup 失败的首因。
            }
            co_return std::unexpected(std::move(Failure));
        }

        /** @brief 在唯一调用者中绑定并提交完整 BND 应答。 */
        [[nodiscard]] auto BindAndReplyCore() -> Net::awaitable<Result>
        {
            const auto Tcp = Retirement_->Tcp();
            bool SuccessReplyAttempted = false;
            std::exception_ptr Exception;
            try
            {
                if (!Tcp)
                {
                    const Prism::Fault::Failure Cause{Prism::Fault::Code::IoError};
                    Retirement_->RecordFailure(Cause);
                    co_return FailureResult(Error::NotOpen, Cause, 0);
                }
                const auto Control = Retirement_->ReadControlEndpoints();
                if (!Control)
                {
                    Retirement_->RecordFailure(Control.error());
                    co_return co_await SendGeneralFailure(
                        Tcp, ReplyFailure{Error::IoError, Control.error(), 0});
                }
                ControlPeer_ = Endpoint(Control->Peer.address(), Control->Peer.port());
                const auto Local = BindSockets(*Control);
                if (!Local) co_return co_await SendGeneralFailure(Tcp, Local.error());
                BoundEndpoint_ = *Local;
                SuccessReplyAttempted = true;
                co_return co_await Tcp->SendAssocReply(
                    ReplyCode::Success, Detail::EndpointToAddress(*Local));
            }
            catch (...)
            {
                Exception = std::current_exception();
            }
            if (Exception)
            {
                const auto Cause = Retirement_->RecordException(Exception);
                if (Tcp && !SuccessReplyAttempted)
                {
                    co_return co_await SendGeneralFailure(
                        Tcp, ReplyFailure{Error::IoError, Cause, 0});
                }
                co_return FailureResult(Error::IoError, Cause, 0);
            }
            co_return FailureResult(Error::IoError,
                {Prism::Fault::Code::Blocked}, 0);
        }

        /** @brief 发布唯一结果后再唤醒全部等待者。 */
        auto Complete(Result Value) -> void
        {
            if (Result_) return;
            Result_ = std::move(Value);
            Running_ = false;
            for (const auto &WeakWaiter : Waiters_)
            {
                if (const auto Waiter = WeakWaiter.lock())
                {
                    Waiter->cancel();
                }
            }
            Waiters_.clear();
        }

        /** @brief 构造单一 typed 协议/传输失败结果。 */
        [[nodiscard]] static auto FailureResult(
            const Error Protocol,
            const Prism::Fault::Failure Transport,
            const std::size_t Bytes) -> Result
        {
            return std::unexpected(ReplyFailure{Protocol, Transport, Bytes});
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<UdpAssocRetirement> Retirement_;
        std::vector<std::weak_ptr<Net::steady_timer>> Waiters_;
        std::optional<Result> Result_;
        std::optional<Endpoint> BoundEndpoint_;
        std::optional<Endpoint> ControlPeer_;
        bool Running_{false};
    };
}
