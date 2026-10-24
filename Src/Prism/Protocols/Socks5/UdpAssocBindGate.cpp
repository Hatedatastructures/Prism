/** @file UdpAssocBindGate.cpp @brief SOCKS5 UDP_ASSOCIATE BND 应答实现。 */
#include <Prism/Protocols/Socks5/UdpAssocBindGate.hpp>

#include "Detail/UdpAddress.hpp"

#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Socks5
{

    auto UdpAssocBindGate::BindAndReplyCore() -> Net::awaitable<Result>
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
            if (!Local)
            {
                co_return co_await SendGeneralFailure(Tcp, Local.error());
            }
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
            Prism::Fault::Failure{Prism::Fault::Code::Blocked}, 0);
    }


    UdpAssocBindGate::UdpAssocBindGate(Net::any_io_executor Executor,
                                       std::shared_ptr<UdpAssocRetirement> Retirement)
        : Executor_(std::move(Executor)), Retirement_(std::move(Retirement))
    {
    }

    [[nodiscard]] auto UdpAssocBindGate::LocalEndpoint() const -> Endpoint
    {
        if (BoundEndpoint_) return *BoundEndpoint_;
        return Retirement_->Ingress().local_endpoint();
    }

    [[nodiscard]] auto UdpAssocBindGate::Run() -> Net::awaitable<Result>
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

    [[nodiscard]] auto UdpAssocBindGate::Enter() noexcept -> Action
    {
        if (Result_) return Action::Completed;
        if (Running_) return Action::Wait;
        Running_ = true;
        return Action::Start;
    }

    [[nodiscard]] auto UdpAssocBindGate::Wait() -> Net::awaitable<Result>
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

    [[nodiscard]] auto UdpAssocBindGate::BindSockets(const UdpAssocRetirement::ControlEndpointSnapshot &Control)
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

    [[nodiscard]] auto UdpAssocBindGate::SocketFailure(const boost::system::error_code ErrorCode)
        -> ReplyFailure
    {
        const auto Cause = Prism::Fault::FromNative(
            static_cast<std::error_code>(ErrorCode));
        Retirement_->RecordFailure(Cause);
        return {Error::IoError, Cause, 0};
    }

    [[nodiscard]] auto UdpAssocBindGate::SendGeneralFailure(
        const std::shared_ptr<Conn<>> &Tcp,
        ReplyFailure Failure) -> Net::awaitable<Result>
    {
        try
        {
            (void)co_await Tcp->SendAssocReply(ReplyCode::GeneralFailure, Address{});
        }
        catch (...)
        {
            // 错误回复写入异常不能覆盖导致初始化失败的首因。
        }
        co_return std::unexpected(std::move(Failure));
    }

    auto UdpAssocBindGate::Complete(Result Value) -> void
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

} // namespace Prism::Socks5
