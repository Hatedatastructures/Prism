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
        auto Host = Destination->Host;
        const auto Port = Destination->Port;
        Preview::Restls::ServerOptions ServerOptions;
        ServerOptions.DialTarget = [Dial = std::move(Dial), Host = std::move(Host), Port](
                                       std::span<const std::uint8_t>)
            -> boost::asio::awaitable<std::pair<Preview::Fault::Code,
                                                Preview::SharedTransmission>>
        {
            Preview::Network::Target Target;
            Target.Host = Host;
            Target.Port = std::to_string(Port);
            co_return co_await Dial(Target);
        };

        auto Session = std::make_shared<Preview::Restls::ServerSession>(
            std::move(ServerOptions));
        Preview::Restls::ServerConfig Config;
        Config.password = std::move(Options.Password);
        Config.Tls13 = Options.Tls13;
        return CarrierAcceptFn(
            [Session, Config = std::move(Config)](Preview::SharedTransmission Inbound)
                -> Net::awaitable<Preview::Recognition::CarrierAcceptResult>
            {
                auto ServerResult = co_await Session->Run(std::move(Inbound), Config);
                Preview::Recognition::CarrierAcceptResult Result;
                Result.Metadata.Carrier = "restls";
                if (ServerResult.Status != Preview::Error::None || !ServerResult.Connection)
                {
                    Result.Code = ServerResult.FaultCode != Preview::Fault::Code::Success
                                      ? ServerResult.FaultCode
                                      : ServerResult.Status == Preview::Error::None
                                            ? Preview::Fault::Code::ProtocolError
                                            : Preview::Fault::ToCode(
                                                  Preview::make_error_code(ServerResult.Status));
                    co_return Result;
                }
                Result.Transport = std::move(ServerResult.Connection);
                co_return Result;
            });
    }

} // namespace Preview::Composition::Recognition
