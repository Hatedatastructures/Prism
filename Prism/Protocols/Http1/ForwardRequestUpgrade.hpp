/**
 * @file ForwardRequestUpgrade.hpp
 * @brief HTTP/1.1 Upgrade 响应门控。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http1/ForwardRequestFraming.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11::Detail
{
    namespace Net = boost::asio;

    enum class UpgradeState : std::uint8_t
    {
        Awaiting,
        Accepted,
        Rejected,
    };

    class UpgradeGate final
    {
    public:
        explicit UpgradeGate(Net::any_io_executor Executor) : Event_(Executor, 1)
        {
        }

        [[nodiscard]] auto Awaiting() const noexcept -> bool
        {
            return State_ == UpgradeState::Awaiting;
        }

        [[nodiscard]] auto Accepted() const noexcept -> bool
        {
            return State_ == UpgradeState::Accepted && !Closed_ && Failure_.Succeeded();
        }

        [[nodiscard]] auto Failure() const noexcept -> const Prism::Fault::Failure &
        {
            return Failure_;
        }

        auto Close() noexcept -> void
        {
            Closed_ = true;
            Signal();
        }

        auto Shutdown() -> void
        {
            if (Awaiting() && Failure_.Succeeded())
            {
                SetFailure(Prism::Fault::FromNative(
                    Prism::make_error_code(Prism::Error::UnexpectedEof)));
            }
        }

        /** @brief 记录取消事实并交付；成功只表示取消请求已在本对象交付。 */
        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult
        {
            SetFailure(Prism::Fault::FromNative(
                std::make_error_code(std::errc::operation_canceled)));
            return {};
        }

        auto Fail(Prism::Fault::Failure Failure) -> void
        {
            SetFailure(std::move(Failure));
        }

        auto Observe(std::span<const std::byte> Buffer) -> void
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

        [[nodiscard]] auto Wait() -> Net::awaitable<bool>
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

    private:
        auto SetFailure(Prism::Fault::Failure Failure) -> void
        {
            if (Failure.Succeeded())
            {
                Failure = Prism::Fault::FromNative(
                    Prism::make_error_code(Prism::Error::IoError));
            }
            Failure_ = std::move(Failure);
            Signal();
        }

        auto Signal() noexcept -> void
        {
            Event_.try_send(boost::system::error_code{});
        }

        std::string Response_;
        UpgradeState State_{UpgradeState::Awaiting};
        Prism::Fault::Failure Failure_;
        bool Closed_{false};
        Net::experimental::channel<void(boost::system::error_code)> Event_;
    };
} // namespace Prism::Http11::Detail
