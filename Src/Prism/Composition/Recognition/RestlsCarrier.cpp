/** @file RestlsCarrier.cpp @brief Restls carrier 配置与接入适配实现。 */

#include <Prism/Composition/Recognition/RestlsCarrier.hpp>

#include <boost/asio/awaitable.hpp>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Restls/Restls.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <charconv>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace Prism::Composition::Recognition
{
    namespace Core = Prism::Recognition;

    namespace
    {

        struct RestlsHostPort final
        {
            std::string Host;
            std::uint16_t Port{0};
        };

        struct RestlsDialTarget final
        {
            Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
            Prism::Network::Target Target;

            struct Request final
            {
                Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
                Prism::Network::Target Target;
            };

            [[nodiscard]] static auto Run(Request Value)
                -> boost::asio::awaitable<std::expected<Prism::SharedTransmission,
                    Prism::Fault::Failure>>;

            [[nodiscard]] auto operator()(std::span<const std::uint8_t>) const
                -> boost::asio::awaitable<std::expected<Prism::SharedTransmission,
                    Prism::Fault::Failure>>;
        };

        struct RestlsServerAccept final
        {
            std::shared_ptr<Prism::Restls::ServerSession> Session;
            Prism::Restls::ServerConfig Config;

            struct Request final
            {
                std::shared_ptr<Prism::Restls::ServerSession> Session;
                Prism::Restls::ServerConfig Config;
                Prism::SharedTransmission Inbound;
            };

            [[nodiscard]] static auto Run(Request Value)
                -> boost::asio::awaitable<Prism::Recognition::CarrierAcceptResult>;

            [[nodiscard]] auto operator()(Core::CarrierAcceptInput Input) const
                -> boost::asio::awaitable<Prism::Recognition::CarrierAcceptResult>;
        };

        [[nodiscard]] auto ParseRestlsPort(std::string_view Value)
            -> std::optional<std::uint16_t>
        {
            std::uint32_t Port = 0;
            const auto [End, Error] = std::from_chars(
                Value.data(), Value.data() + Value.size(), Port);
            if (Value.empty() || Error != std::errc{} || End != Value.data() + Value.size() ||
                Port == 0U || Port > 65535U)
            {
                return std::nullopt;
            }
            return static_cast<std::uint16_t>(Port);
        }

        [[nodiscard]] auto ParseRestlsHostPort(const std::string_view Value)
            -> std::optional<RestlsHostPort>
        {
            if (Value.empty())
            {
                return std::nullopt;
            }
            if (Value.front() == '[')
            {
                const auto Close = Value.find(']');
                if (Close == std::string_view::npos)
                {
                    return std::nullopt;
                }
                const auto Host = Value.substr(1U, Close - 1U);
                if (Close + 1U == Value.size())
                {
                    return RestlsHostPort{std::string(Host), 443};
                }
                if (Value[Close + 1U] != ':')
                {
                    return std::nullopt;
                }
                const auto Port = ParseRestlsPort(Value.substr(Close + 2U));
                return Host.empty() || !Port
                    ? std::nullopt
                    : std::optional<RestlsHostPort>{RestlsHostPort{std::string(Host), *Port}};
            }

            const auto Colon = Value.rfind(':');
            if (Colon == std::string_view::npos)
            {
                return RestlsHostPort{std::string(Value), 443};
            }
            if (Colon == 0U || Value.find(':') != Colon)
            {
                return std::nullopt;
            }
            const auto Port = ParseRestlsPort(Value.substr(Colon + 1U));
            return !Port
                ? std::nullopt
                : std::optional<RestlsHostPort>{
                    RestlsHostPort{std::string(Value.substr(0, Colon)), *Port}};
        }

        auto RestlsDialTarget::Run(Request Value)
            -> boost::asio::awaitable<std::expected<Prism::SharedTransmission,
                Prism::Fault::Failure>>
        {
            co_return co_await Value.Dial(Value.Target);
        }

        auto RestlsDialTarget::operator()(std::span<const std::uint8_t>) const
            -> boost::asio::awaitable<std::expected<Prism::SharedTransmission,
                Prism::Fault::Failure>>
        {
            return Run(Request{Dial, Target});
        }

        auto RestlsServerAccept::Run(Request Value)
            -> boost::asio::awaitable<Prism::Recognition::CarrierAcceptResult>
        {
            auto ServerResult = co_await Value.Session->Run(
                std::move(Value.Inbound), Value.Config);
            Prism::Recognition::CarrierAcceptResult Result;
            Result.Metadata.Carrier = "restls";
            if (!ServerResult)
            {
                const auto Failure = Prism::Restls::ToFaultFailure(ServerResult.error());
                Result.Code = Failure.Code;
                Result.NativeError = ServerResult.error().Native;
                co_return Result;
            }
            Result.Transport = std::move(*ServerResult);
            co_return Result;
        }

        auto RestlsServerAccept::operator()(Core::CarrierAcceptInput Input) const
            -> boost::asio::awaitable<Prism::Recognition::CarrierAcceptResult>
        {
            return Run(Request{Session, Config, std::move(Input.Inbound)});
        }

    } // namespace

    auto MakeConfiguredRestlsServerAccept(RestlsCarrierOptions Options)
        -> std::expected<CarrierAcceptFn, RestlsCarrierBuildError>
    {
        if (Options.Password.empty())
        {
            return std::unexpected(RestlsCarrierBuildError::MissingPassword);
        }
        if (!Options.Dial)
        {
            return std::unexpected(RestlsCarrierBuildError::MissingDial);
        }
        const auto Destination = ParseRestlsHostPort(Options.Host);
        if (!Destination)
        {
            return std::unexpected(RestlsCarrierBuildError::InvalidDestination);
        }

        auto Dial = std::move(Options.Dial);
        auto Host = Prism::Network::ParseHost(Destination->Host);
        if (!Host) return std::unexpected(RestlsCarrierBuildError::InvalidDestination);
        Prism::Network::Target Target{std::move(*Host), Destination->Port};
        Prism::Restls::ServerOptions ServerOptions;
        ServerOptions.DialTarget = RestlsDialTarget{
            std::move(Dial), std::move(Target)};

        auto Session = std::make_shared<Prism::Restls::ServerSession>(
            std::move(ServerOptions));
        Prism::Restls::ServerConfig Config;
        Config.password = std::move(Options.Password);
        Config.Tls13 = Options.Tls13;
        return CarrierAcceptFn(
            RestlsServerAccept{std::move(Session), std::move(Config)});
    }

} // namespace Prism::Composition::Recognition
