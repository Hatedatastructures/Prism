/** @file Config.cpp @brief DNS 上游地址配置解析实现。 */
#include <Prism/Net/Dns/Config.hpp>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

namespace Prism::Network::Dns
{
    auto TransparentStringHash::operator()(const std::string_view Value) const noexcept
        -> std::size_t
    {
        std::size_t Hash = 14695981039346656037ull;
        for (const auto Character : Value)
        {
            Hash ^= static_cast<std::uint8_t>(Character);
            Hash *= 1099511628211ull;
        }
        return Hash;
    }

    namespace
    {
        struct ServerAddressParts final
        {
            std::string_view Host;
            std::uint16_t Port{0};
            bool HasPort{false};
        };

        [[nodiscard]] auto ParsePortValue(const std::string_view Value)
            -> std::optional<std::uint16_t>
        {
            if (Value.empty() || Value.size() > 5)
            {
                return std::nullopt;
            }
            std::uint32_t Number = 0;
            const auto Parsed = std::from_chars(Value.data(), Value.data() + Value.size(), Number);
            if (Parsed.ec != std::errc{} || Parsed.ptr != Value.data() + Value.size() ||
                Number == 0 || Number > 65535)
            {
                return std::nullopt;
            }
            return static_cast<std::uint16_t>(Number);
        }

        [[nodiscard]] auto SplitServerAuthority(const std::string_view Authority)
            -> ServerAddressParts
        {
            if (Authority.starts_with('['))
            {
                const auto Close = Authority.find(']');
                if (Close == std::string_view::npos)
                {
                    return {Authority, 0, false};
                }
                const auto Host = Authority.substr(1, Close - 1);
                if (Close + 1 < Authority.size() && Authority[Close + 1] == ':')
                {
                    if (const auto Port = ParsePortValue(Authority.substr(Close + 2)))
                    {
                        return {Host, *Port, true};
                    }
                }
                return {Host, 0, false};
            }

            const auto Colon = Authority.rfind(':');
            if (Colon != std::string_view::npos && Authority.find(':') == Colon)
            {
                if (const auto Port = ParsePortValue(Authority.substr(Colon + 1)))
                {
                    return {Authority.substr(0, Colon), *Port, true};
                }
            }
            return {Authority, 0, false};
        }
    }

    auto ParseServer(std::string_view Input) -> Server
    {
        Server ServerConfig;
        struct SchemeMapping final
        {
            std::string_view Prefix;
            Protocol Proto;
            std::uint16_t DefaultPort;
        };
        static constexpr SchemeMapping Mappings[] = {
            {"udp://", Protocol::Udp, 53}, {"tcp://", Protocol::Tcp, 53},
            {"tls://", Protocol::Tls, 853}, {"https://", Protocol::Https, 443},
        };

        for (const auto &Mapping : Mappings)
        {
            if (!Input.starts_with(Mapping.Prefix))
            {
                continue;
            }
            ServerConfig.Proto = Mapping.Proto;
            ServerConfig.Port = Mapping.DefaultPort;
            Input.remove_prefix(Mapping.Prefix.size());
            break;
        }

        if (ServerConfig.Proto == Protocol::Https)
        {
            if (const auto Slash = Input.find('/'); Slash != std::string_view::npos)
            {
                ServerConfig.HttpPath = std::string(Input.substr(Slash));
                Input = Input.substr(0, Slash);
            }
        }

        const auto Parts = SplitServerAuthority(Input);
        ServerConfig.Address = std::string(Parts.Host);
        ServerConfig.Hostname = ServerConfig.Address;
        if (Parts.HasPort)
        {
            ServerConfig.Port = Parts.Port;
        }
        return ServerConfig;
    }
}
