/**
 * @file RestlsCarrier.hpp
 * @brief 配置驱动的 Restls 中间人 carrier 构造。
 */
#pragma once

#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Protocols/Restls/Server.hpp>
#include <Preview/Runtime/Middleware/Builtin/Dial.hpp>

#include <charconv>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace Preview::Composition::Recognition
{

    namespace Core = Preview::Recognition;

    enum class RestlsCarrierBuildError : std::uint8_t
    {
        MissingPassword,
        MissingDial,
        InvalidDestination,
    };

    struct RestlsCarrierOptions final
    {
        std::string Host;
        std::string Password;
        std::string RestlsScript;
        bool Tls13{false};
        Preview::Middleware::Builtin::DialMiddleware::DialFn Dial;
    };

    namespace Detail
    {

        struct RestlsHostPort final
        {
            std::string Host;
            std::uint16_t Port{0};
        };

        struct RestlsDialTarget final
        {
            Preview::Middleware::Builtin::DialMiddleware::DialFn Dial;
            Preview::Network::Target Target;

            struct Request final
            {
                Preview::Middleware::Builtin::DialMiddleware::DialFn Dial;
                Preview::Network::Target Target;
            };

            [[nodiscard]] static auto Run(Request Value)
                -> boost::asio::awaitable<std::expected<Preview::SharedTransmission,
                                                        Preview::Fault::Failure>>
            {
                co_return co_await Value.Dial(Value.Target);
            }

            [[nodiscard]] auto operator()(std::span<const std::uint8_t>) const
                -> boost::asio::awaitable<std::expected<Preview::SharedTransmission,
                                                        Preview::Fault::Failure>>
            {
                return Run(Request{Dial, Target});
            }
        };

        struct RestlsServerAccept final
        {
            std::shared_ptr<Preview::Restls::ServerSession> Session;
            Preview::Restls::ServerConfig Config;

            struct Request final
            {
                std::shared_ptr<Preview::Restls::ServerSession> Session;
                Preview::Restls::ServerConfig Config;
                Preview::SharedTransmission Inbound;
            };

            [[nodiscard]] static auto Run(Request Value)
                -> Net::awaitable<Preview::Recognition::CarrierAcceptResult>
            {
                auto ServerResult = co_await Value.Session->Run(
                    std::move(Value.Inbound), Value.Config);
                Preview::Recognition::CarrierAcceptResult Result;
                Result.Metadata.Carrier = "restls";
                if (!ServerResult)
                {
                    const auto Failure = Preview::Restls::ToFaultFailure(ServerResult.error());
                    Result.Code = Failure.Code;
                    Result.NativeError = ServerResult.error().Native;
                    co_return Result;
                }
                Result.Transport = std::move(*ServerResult);
                co_return Result;
            }

            [[nodiscard]] auto operator()(Core::CarrierAcceptInput Input) const
                -> Net::awaitable<Preview::Recognition::CarrierAcceptResult>
            {
                return Run(Request{Session, Config, std::move(Input.Inbound)});
            }
        };

        [[nodiscard]] inline auto ParseRestlsPort(std::string_view Value)
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

        [[nodiscard]] inline auto ParseRestlsHostPort(std::string_view Value)
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

    } // namespace Detail

    [[nodiscard]] inline auto MakeConfiguredRestlsServerAccept(
        RestlsCarrierOptions Options) -> std::expected<CarrierAcceptFn, RestlsCarrierBuildError>
    {
        if (Options.Password.empty())
        {
            return std::unexpected(RestlsCarrierBuildError::MissingPassword);
        }
        if (!Options.Dial)
        {
            return std::unexpected(RestlsCarrierBuildError::MissingDial);
        }
        const auto Destination = Detail::ParseRestlsHostPort(Options.Host);
        if (!Destination)
        {
            return std::unexpected(RestlsCarrierBuildError::InvalidDestination);
        }

        auto Dial = std::move(Options.Dial);
        auto Host = Preview::Network::ParseHost(Destination->Host);
        if (!Host) return std::unexpected(RestlsCarrierBuildError::InvalidDestination);
        Preview::Network::Target Target{std::move(*Host), Destination->Port};
        Preview::Restls::ServerOptions ServerOptions;
        ServerOptions.DialTarget = Detail::RestlsDialTarget{
            std::move(Dial), std::move(Target)};

        auto Session = std::make_shared<Preview::Restls::ServerSession>(
            std::move(ServerOptions));
        Preview::Restls::ServerConfig Config;
        Config.password = std::move(Options.Password);
        Config.Tls13 = Options.Tls13;
        return CarrierAcceptFn(
            Detail::RestlsServerAccept{std::move(Session), std::move(Config)});
    }

} // namespace Preview::Composition::Recognition
