/** @file ShadowtlsCarrier.cpp @brief ShadowTLS carrier 配置适配实现。 */

#include <Prism/Composition/Recognition/ShadowtlsCarrier.hpp>

#include <Prism/Composition/Recognition/Detail/CarrierRunners.hpp>

#include <charconv>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace Prism::Composition::Recognition
{
    [[nodiscard]] auto RunShadowtlsServerAccept(
        std::shared_ptr<Prism::Shadowtls::ServerSession> Session,
        Prism::Shadowtls::ServerConfig Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        auto ServerResult = co_await Session->Run(std::move(Input.Inbound), Config);
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "shadowtls";
        if (!ServerResult)
        {
            Result.Code = ServerResult.error().Code;
            Result.NativeError = ServerResult.error().Native;
            co_return Result;
        }
        Result.Transport = std::move(*ServerResult);
        co_return Result;
    }

    [[nodiscard]] auto MakeShadowtlsServerAccept(
        Prism::Shadowtls::ServerOptions Options,
        Prism::Shadowtls::ServerConfig Config) -> CarrierAcceptFn
    {
        auto Session = std::make_shared<Prism::Shadowtls::ServerSession>(std::move(Options));
        return [Session, Config = std::move(Config)](Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunShadowtlsServerAccept(Session, Config, std::move(Input));
        };
    }

    namespace detail
    {

        auto ShadowtlsDialTarget::Run(Request Value)
            -> boost::asio::awaitable<Prism::Shadowtls::Result<Prism::SharedTransmission>>
        {
            auto Dialed = co_await Value.Dial(Value.Target);
            if (!Dialed)
            {
                co_return std::unexpected(Prism::Shadowtls::FailureFromFault(Dialed.error()));
            }
            if (!*Dialed)
            {
                co_return std::unexpected(
                    Prism::Shadowtls::FailureFromError(Prism::Error::NotOpen));
            }
            co_return std::move(*Dialed);
        }

        auto ShadowtlsDialTarget::operator()(const std::span<const std::uint8_t>) const
            -> boost::asio::awaitable<Prism::Shadowtls::Result<Prism::SharedTransmission>>
        {
            return Run(Request{Dial, Target});
        }

        auto ParseShadowtlsPort(const std::string_view Value)
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

        auto ParseShadowtlsHostPort(const std::string_view Value)
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

    auto MakeConfiguredShadowtlsServerAccept(ShadowtlsCarrierOptions Options)
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
