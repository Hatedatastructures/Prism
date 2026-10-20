/**
 * @file ForwardRequestUpgrade.hpp
 * @brief HTTP/1.1 Upgrade 响应门控。
 */

#pragma once

#include <cstddef>
#include <cstdint>
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
#include <Prism/Protocols/Http1/Detail/ForwardRequestFraming.hpp>
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

        auto Close() noexcept -> void;

        auto Shutdown() -> void;

        /** @brief 记录取消事实并交付；成功只表示取消请求已在本对象交付。 */
        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult;

        auto Fail(Prism::Fault::Failure Failure) -> void;

        auto Observe(std::span<const std::byte> Buffer) -> void;

        [[nodiscard]] auto Wait() -> Net::awaitable<bool>;

    private:
        auto SetFailure(Prism::Fault::Failure Failure) -> void;

        auto Signal() noexcept -> void;

        std::string Response_;
        UpgradeState State_{UpgradeState::Awaiting};
        Prism::Fault::Failure Failure_;
        bool Closed_{false};
        Net::experimental::channel<void(boost::system::error_code)> Event_;
    };
} // namespace Prism::Http11::Detail
