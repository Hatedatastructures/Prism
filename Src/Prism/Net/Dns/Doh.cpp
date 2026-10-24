/** @file Doh.cpp @brief DNS over HTTPS 传输实现。 */
#include <Prism/Net/Dns/Doh.hpp>

#include "Detail/DohResponse.hpp"
#include "Detail/TlsTransport.hpp"

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <utility>

namespace Prism::Network::Dns::Detail
{
    struct DohState final
    {
        explicit DohState(DohOptions Options)
            : Tls(std::move(Options.Executor), std::move(Options.Context)),
              HttpPath(std::move(Options.HttpPath)), HostHeader(std::move(Options.HostHeader))
        {
        }

        TlsTransport Tls;
        std::string HttpPath;
        std::string HostHeader;
    };
}

namespace Prism::Network::Dns
{
    namespace
    {
        struct ConnectInput final
        {
            Net::ip::tcp::endpoint Endpoint;
            Server ServerConfig;
            Detail::AttemptDeadline Deadline;
        };

        [[nodiscard]] auto ConnectOnState(std::shared_ptr<Detail::DohState> Owner,
            ConnectInput Input)
            -> Net::awaitable<boost::system::error_code>
        {
            co_return co_await Owner->Tls.Connect(
                Input.Endpoint, Input.ServerConfig, Input.Deadline);
        }

        [[nodiscard]] auto SendRequest(std::shared_ptr<Detail::DohState> Owner,
            const std::span<const std::uint8_t> Wire,
            const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>
        {
            auto Request = std::string{};
            Request.reserve(224 + Owner->HttpPath.size() + Owner->HostHeader.size() + Wire.size());
            Request += "POST ";
            Request += Owner->HttpPath;
            Request += " HTTP/1.1\r\nHost: ";
            Request += Owner->HostHeader;
            Request += "\r\nContent-Type: application/dns-message\r\n";
            Request += "Accept: application/dns-message\r\nContent-Length: ";
            Request += std::to_string(Wire.size());
            Request += "\r\nConnection: keep-alive\r\n\r\n";
            Request.append(reinterpret_cast<const char *>(Wire.data()), Wire.size());

            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Request.data()), Request.size());
            co_return co_await Owner->Tls.WriteAll(Bytes, Deadline);
        }

    }

    DohTransport::DohTransport(DohOptions Options)
        : State_(std::make_shared<Detail::DohState>(std::move(Options)))
    {
    }

    auto DohTransport::Connect(const Net::ip::tcp::endpoint &Endpoint,
        const Server &ServerConfig, const Detail::AttemptDeadline Deadline)
        -> Net::awaitable<boost::system::error_code>
    {
        return ConnectOnState(State_, ConnectInput{Endpoint, ServerConfig, Deadline});
    }

    auto DohTransport::Send(const std::span<const std::uint8_t> Wire,
        const Detail::AttemptDeadline Deadline)
        -> Net::awaitable<boost::system::error_code>
    {
        return SendRequest(State_, Wire, Deadline);
    }

    auto DohTransport::Receive(const Detail::AttemptDeadline Deadline)
        -> Net::awaitable<EcResult<std::vector<std::uint8_t>>>
    {
        return Detail::ReceiveDohResponse(State_, Deadline);
    }

    auto DohTransport::IsOpen() const -> bool
    {
        return State_->Tls.IsOpen();
    }

    auto DohTransport::Close() -> void
    {
        State_->Tls.Close();
    }
} // namespace Prism::Network::Dns
