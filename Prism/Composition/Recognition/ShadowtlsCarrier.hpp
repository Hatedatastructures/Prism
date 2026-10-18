/**
 * @file ShadowtlsCarrier.hpp
 * @brief 配置驱动的 ShadowTLS carrier 构造。
 * @details 将配置中的 HandshakeDest/password 与 runtime DialFn 绑定到真实
 *          ShadowTLS ServerSession；不在 composition 层保存 secret 解析器或
 *          伪造 outbound transport。
 */
#pragma once

#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Shadowtls/Server.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>

#include <charconv>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace Prism::Composition::Recognition
{

    enum class ShadowtlsCarrierBuildError : std::uint8_t
    {
        MissingPassword,
        MissingDial,
        InvalidDestination,
    };

    struct ShadowtlsCarrierOptions final
    {
        std::string HandshakeDest;
        std::string Password;
        Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
    };

    namespace detail
    {

        struct ShadowtlsHostPort final
        {
            std::string Host;
            std::uint16_t Port{0};
        };

        struct ShadowtlsDialTarget final
        {
            Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
            Prism::Network::Target Target;

            struct Request final
            {
                Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
                Prism::Network::Target Target;
            };

            [[nodiscard]] static auto Run(Request Value)
                -> boost::asio::awaitable<Prism::Shadowtls::Result<Prism::SharedTransmission>>
            {
                auto Dialed = co_await Value.Dial(Value.Target);
                if (!Dialed)
                    co_return std::unexpected(Prism::Shadowtls::FailureFromFault(Dialed.error()));
                if (!*Dialed)
                    co_return std::unexpected(Prism::Shadowtls::FailureFromError(Prism::Error::NotOpen));
                co_return std::move(*Dialed);
            }

            [[nodiscard]] auto operator()(std::span<const std::uint8_t>) const
                -> boost::asio::awaitable<Prism::Shadowtls::Result<Prism::SharedTransmission>>
            {
                return Run(Request{Dial, Target});
            }
        };

        [[nodiscard]] inline auto ParseShadowtlsPort(std::string_view Value)
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

        [[nodiscard]] inline auto ParseShadowtlsHostPort(std::string_view Value)
            -> std::optional<ShadowtlsHostPort>
        {
            std::string_view Host;
            std::string_view PortText;
            if (!Value.empty() && Value.front() == '[')
            {
                const auto Close = Value.find(']');
                if (Close == std::string_view::npos || Close + 2U > Value.size() ||
                    Value[Close + 1U] != ':')
                {
                    return std::nullopt;
                }
                Host = Value.substr(1U, Close - 1U);
                PortText = Value.substr(Close + 2U);
            }
            else
            {
                const auto Colon = Value.rfind(':');
                if (Colon == std::string_view::npos || Colon == 0U || Colon + 1U >= Value.size() ||
                    Value.find(':') != Colon)
                {
                    return std::nullopt;
                }
                Host = Value.substr(0, Colon);
                PortText = Value.substr(Colon + 1U);
            }
            const auto Port = ParseShadowtlsPort(PortText);
            if (Host.empty() || !Port)
            {
                return std::nullopt;
            }
            return ShadowtlsHostPort{std::string(Host), *Port};
        }

    } // namespace detail

    [[nodiscard]] inline auto MakeConfiguredShadowtlsServerAccept(
        ShadowtlsCarrierOptions Options)
        -> std::expected<CarrierAcceptFn, ShadowtlsCarrierBuildError>
    {
        if (Options.Password.empty())
        {
            return std::unexpected(ShadowtlsCarrierBuildError::MissingPassword);
        }
        if (!Options.Dial)
        {
            return std::unexpected(ShadowtlsCarrierBuildError::MissingDial);
        }
        const auto Destination = detail::ParseShadowtlsHostPort(Options.HandshakeDest);
        if (!Destination)
        {
            return std::unexpected(ShadowtlsCarrierBuildError::InvalidDestination);
        }

        auto Dial = std::move(Options.Dial);
        auto Host = Prism::Network::ParseHost(Destination->Host);
        if (!Host) return std::unexpected(ShadowtlsCarrierBuildError::InvalidDestination);
        Prism::Network::Target Target{std::move(*Host), Destination->Port};
        Prism::Shadowtls::ServerOptions RelayOptions;
        RelayOptions.DialTarget = detail::ShadowtlsDialTarget{
            std::move(Dial), std::move(Target)};

        return CarrierAcceptFn(MakeShadowtlsServerAccept(
            std::move(RelayOptions), Prism::Shadowtls::ServerConfig{std::move(Options.Password)}));
    }

} // namespace Prism::Composition::Recognition
