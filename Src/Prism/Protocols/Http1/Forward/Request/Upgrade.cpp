/**
 * @file Upgrade.cpp
 * @brief HTTP/1.1 Upgrade 响应门控状态与事件实现。
 */
#include <Prism/Protocols/Http1/Forward/Request/Detail/Upgrade.hpp>

#include <algorithm>
#include <utility>

namespace Prism::Http11::Detail
{

    auto UpgradeGate::Close() noexcept -> void
    {
        Closed_ = true;
        Signal();
    }

    auto UpgradeGate::Shutdown() -> void
    {
        if (Awaiting() && Failure_.Succeeded())
        {
            SetFailure(Prism::Fault::FromNative(
                Prism::make_error_code(Prism::Error::UnexpectedEof)));
        }
    }

    auto UpgradeGate::Cancel() -> Prism::Transmission::ControlResult
    {
        SetFailure(Prism::Fault::FromNative(
            std::make_error_code(std::errc::operation_canceled)));
        return {};
    }

    auto UpgradeGate::Fail(Prism::Fault::Failure Failure) -> void
    {
        SetFailure(std::move(Failure));
    }

    auto UpgradeGate::Observe(const std::span<const std::byte> Buffer) -> void
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size() && Awaiting())
        {
            if (Response_.size() >= MaxHdrSize)
            {
                Fail(Prism::Fault::FromNative(
                    Prism::make_error_code(Prism::Error::BadMessage)));
                return;
            }
            const auto Count = (std::min)(Buffer.size() - Offset,
                                          MaxHdrSize - Response_.size());
            Response_.append(reinterpret_cast<const char *>(Buffer.data() + Offset), Count);
            Offset += Count;
            while (true)
            {
                const auto End = Response_.find("\r\n\r\n");
                if (End == std::string::npos)
                {
                    break;
                }
                const auto HeaderSize = End + 4U;
                const auto Status = ParseUpgradeStatus(
                    std::string_view(Response_).substr(0, HeaderSize));
                if (!Status)
                {
                    Fail(Prism::Fault::FromNative(
                        Prism::make_error_code(Prism::Error::BadMessage)));
                    return;
                }
                if (*Status == 101)
                {
                    State_ = UpgradeState::Accepted;
                    Signal();
                    return;
                }
                Response_.erase(0, HeaderSize);
                if (*Status < 100 || *Status >= 200)
                {
                    State_ = UpgradeState::Rejected;
                    Signal();
                    return;
                }
            }
            if (Response_.size() >= MaxHdrSize &&
                Response_.find("\r\n\r\n") == std::string::npos)
            {
                Fail(Prism::Fault::FromNative(
                    Prism::make_error_code(Prism::Error::BadMessage)));
                return;
            }
        }
    }

    auto UpgradeGate::Wait() -> Net::awaitable<bool>
    {
        while (Awaiting() && !Closed_ && Failure_.Succeeded())
        {
            boost::system::error_code EventError;
            co_await Event_.async_receive(Net::redirect_error(Net::use_awaitable, EventError));
            if (EventError)
            {
                SetFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(EventError)));
                co_return false;
            }
        }
        if (Failure_.Failed())
        {
            co_return false;
        }
        co_return Accepted();
    }

    auto UpgradeGate::SetFailure(Prism::Fault::Failure Failure) -> void
    {
        if (Failure.Succeeded())
        {
            Failure = Prism::Fault::FromNative(
                Prism::make_error_code(Prism::Error::IoError));
        }
        Failure_ = std::move(Failure);
        Signal();
    }

    auto UpgradeGate::Signal() noexcept -> void
    {
        Event_.try_send(boost::system::error_code{});
    }

} // namespace Prism::Http11::Detail
