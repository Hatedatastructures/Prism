/** @file HttpServer.cpp @brief Operations HTTP listener 与排空实现。 */
#include <Prism/Operations/HttpServer.hpp>
#include <Prism/Operations/Http/Detail/Lifecycle.hpp>
#include <Prism/Operations/Http/Detail/Connection.hpp>
#include <Prism/Operations/HttpRequestSecurity.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace Prism::Operations
{
    HttpServer::HttpServer(const Options &OptionsValue)
        : State_(std::make_shared<State>(OptionsValue))
    {
    }

    HttpServer::~HttpServer() noexcept
    {
        ForceCloseOnDestruction();
    }

    auto HttpServer::Start() -> Net::awaitable<HttpServerStartResult>
    {
        const auto StateValue = State_;
        if (!StateValue->Bootstrap)
        {
            co_return std::unexpected(
                boost::system::errc::make_error_code(boost::system::errc::invalid_argument));
        }
        co_await Net::post(StateValue->StateStrand, Net::use_awaitable);
        co_return HttpConnection::StartOnStateStrand(StateValue);
    }

    auto HttpServer::CloseAdmission() noexcept -> std::expected<void, Prism::Fault::Failure>
    {
        const auto StateValue = State_;
        try
        {
            Net::post(StateValue->StateStrand,
                [StateValue]
                {
                    StateValue->StopRequested.store(true, std::memory_order_release);
                    HttpConnection::CloseAdmissionOnStateStrand(StateValue);
                });
        }
        catch (...)
        {
            StateValue->StateOperationFailed.store(true, std::memory_order_release);
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        return {};
    }

    auto HttpServer::ForceCloseOnDestruction() noexcept -> void
    {
        const auto StateValue = State_;
        try
        {
            Net::post(StateValue->StateStrand,
                [StateValue]
                {
                    if (!StateValue->StopRequested.exchange(true, std::memory_order_acq_rel))
                        HttpConnection::CloseOnStateStrand(StateValue);
                });
        }
        catch (...)
        {
            StateValue->Started.store(false, std::memory_order_release);
            StateValue->Running.store(false, std::memory_order_release);
            StateValue->StopRequested.store(true, std::memory_order_release);
            StateValue->StateOperationFailed.store(true, std::memory_order_release);
        }
    }

    auto HttpServer::Drain(const Deadline Limit) -> Net::awaitable<DrainResult>
    {
        return DrainOnState(State_, Limit);
    }

    auto HttpServer::DrainOnState(std::shared_ptr<State> StateValue, const Deadline Limit)
        -> Net::awaitable<DrainResult>
    {
        co_await Net::post(StateValue->StateStrand, Net::use_awaitable);
        StateValue->StopRequested.store(true, std::memory_order_release);
        StateValue->Draining.store(true, std::memory_order_release);
        HttpConnection::CloseAdmissionOnStateStrand(StateValue);
        const auto ConfiguredDeadline = std::chrono::steady_clock::now() + StateValue->DrainTimeout;
        if (!StateValue->DrainDeadline)
        {
            StateValue->DrainDeadline = std::min(Limit, ConfiguredDeadline);
        }
        else
        {
            StateValue->DrainDeadline = std::min(*StateValue->DrainDeadline, Limit);
        }

        while (true)
        {
            const auto RemainingConnections =
                StateValue->ActiveConnectionCount.load(std::memory_order_acquire);
            if (StateValue->StateOperationFailed.load(std::memory_order_acquire))
            {
                HttpConnection::CloseConnectionsOnStateStrand(StateValue);
                co_return HttpConnection::MakeStateFailureDrainResult(
                    StateValue, RemainingConnections);
            }
            if (RemainingConnections == 0U && StateValue->AcceptLoopCompleted)
            {
                StateValue->Drained.store(true, std::memory_order_release);
                co_return DrainResult{{}, 0U};
            }
            if (StateValue->DrainTimerExpired ||
                std::chrono::steady_clock::now() >= *StateValue->DrainDeadline)
            {
                StateValue->DrainTimerExpired = true;
                HttpConnection::CloseConnectionsOnStateStrand(StateValue);
                co_return DrainResult{
                    Prism::Fault::Failure{Prism::Fault::Code::Timeout,
                        std::make_error_code(std::errc::timed_out)},
                    RemainingConnections};
            }
            if (!StateValue->DrainTimerArmed)
            {
                StateValue->DrainTimer.expires_at(*StateValue->DrainDeadline);
                StateValue->DrainTimerArmed = true;
            }

            boost::system::error_code Error;
            co_await StateValue->DrainTimer.async_wait(
                Net::redirect_error(Net::use_awaitable, Error));
            StateValue->DrainTimerArmed = false;
            if (Error && Error != Net::error::operation_aborted)
            {
                const auto RemainingAfterWait =
                    StateValue->ActiveConnectionCount.load(std::memory_order_acquire);
                HttpConnection::CloseConnectionsOnStateStrand(StateValue);
                co_return DrainResult{
                    Prism::Fault::FromNative(static_cast<std::error_code>(Error)),
                    RemainingAfterWait};
            }
            if (!Error) StateValue->DrainTimerExpired = true;
        }
    }

    auto HttpServer::LocalEndpoint() const -> Endpoint
    {
        return State_->LocalEndpoint;
    }

    auto HttpServer::IsRunning() const noexcept -> bool
    {
        return State_->Running.load(std::memory_order_acquire) &&
               !State_->StopRequested.load(std::memory_order_acquire);
    }
} // namespace Prism::Operations

namespace Prism::Operations::HttpDetail::RequestSecurity
{
    namespace
    {
        /** @brief 按实际 loopback endpoint 构造唯一 IP literal authority。 */
        [[nodiscard]] auto MakeAuthority(const HttpServer::Endpoint &Endpoint)
            -> std::optional<std::string>
        {
            const auto AddressValue = Endpoint.address();
            if (!AddressValue.is_loopback())
            {
                return std::nullopt;
            }
            auto Authority = AddressValue.to_string();
            if (AddressValue.is_v6())
            {
                Authority = "[" + Authority + "]";
            }
            Authority.append(":").append(std::to_string(Endpoint.port()));
            return Authority;
        }

        /** @brief 将十六进制字符解码为半字节；非法字符返回哨兵值。 */
        [[nodiscard]] auto HexNibble(const char Value) noexcept -> std::uint8_t
        {
            if (Value >= '0' && Value <= '9')
            {
                return static_cast<std::uint8_t>(Value - '0');
            }
            if (Value >= 'a' && Value <= 'f')
            {
                return static_cast<std::uint8_t>(Value - 'a' + 10);
            }
            if (Value >= 'A' && Value <= 'F')
            {
                return static_cast<std::uint8_t>(Value - 'A' + 10);
            }
            return 0xffU;
        }

        /** @brief 用 BoringSSL constant-time 比较固定长度 bearer token。 */
        [[nodiscard]] auto HasValidCommandToken(
            const HttpRequest &Request,
            const BootstrapIdentity &Identity) noexcept -> bool
        {
            constexpr std::string_view Prefix{"Bearer "};
            constexpr auto TokenBytes = BootstrapIdentity::CommandToken{}.size();
            if (Request.Authorization.size() != Prefix.size() + TokenBytes * 2U ||
                !Request.Authorization.starts_with(Prefix))
            {
                return false;
            }
            BootstrapIdentity::CommandToken Candidate{};
            bool ValidHex = true;
            for (std::size_t Index = 0; Index < Candidate.size(); ++Index)
            {
                const auto High = HexNibble(Request.Authorization[Prefix.size() + Index * 2U]);
                const auto Low = HexNibble(Request.Authorization[Prefix.size() + Index * 2U + 1U]);
                ValidHex = ValidHex && High < 16U && Low < 16U;
                Candidate[Index] = static_cast<std::uint8_t>(
                    ((High & 0x0fU) << 4U) | (Low & 0x0fU));
            }
            const auto Equal = CRYPTO_memcmp(
                Candidate.data(), Identity.Token().data(), Candidate.size()) == 0;
            return ValidHex && Equal;
        }
    }

    auto IsAuthorized(
        const HttpRequest &Request,
        const HttpServer::Endpoint &LocalEndpoint,
        const BootstrapIdentity &Identity) -> bool
    {
        const auto Authority = MakeAuthority(LocalEndpoint);
        if (!Authority || Request.Host != *Authority)
        {
            return false;
        }
        if (!Request.Origin.empty() && Request.Origin != "http://" + *Authority)
        {
            return false;
        }
        return Request.Method != "POST" || HasValidCommandToken(Request, Identity);
    }
}
