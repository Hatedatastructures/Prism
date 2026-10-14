/**
 * @file CarrierConfiguration.hpp
 * @brief TCP TLS carrier 的独立 typed 配置模型。
 */
#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace Preview::Contract
{
    struct NativeTlsOptions final
    {
        std::string CertificateFile;
        std::string PrivateKeyFile;
    };

    struct RealityOptions final
    {
        std::string HandshakeTarget;
        std::vector<std::string> ServerNames;
        std::string PrivateKeyRef;
        std::vector<std::string> ShortIds;
    };

    struct ShadowTlsOptions final
    {
        std::uint32_t Version{3};
        std::string PasswordSecretRef;
        std::string HandshakeDest;
        std::vector<std::string> ServerNames;
        bool StrictMode{true};
        std::uint32_t HandshakeTimeoutMs{5000};
    };

    struct RestlsOptions final
    {
        std::vector<std::string> ServerNames;
        std::string Host;
        std::string PasswordSecretRef;
        std::string VersionHint;
        std::string RestlsScript;
        std::uint32_t HandshakeTimeoutMs{5000};
    };

    struct WebSocketOptions final
    {
        std::string Path{"/"};
        std::string Host;
    };

    struct XhttpOptions final
    {
        std::string Path{"/"};
        std::string Host;
        std::string Mode{"StreamOne"};
    };

    struct GunOptions final
    {
        std::vector<std::string> ServerNames;
        std::string Mode{"GunLite"};
        std::string Path{"/GunService/Tun"};
        std::string ServiceName{"GunService"};
    };

    using CarrierOptions = std::variant<NativeTlsOptions, RealityOptions, ShadowTlsOptions,
        RestlsOptions, WebSocketOptions, XhttpOptions, GunOptions>;

    struct CarrierMatchOptions final
    {
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        std::int32_t Priority{0};
        bool Fallback{false};
    };

    struct CarrierConfiguration final
    {
        std::string Id;
        std::string Name;
        std::string Builtin;
        std::vector<std::string> Requires;
        CarrierMatchOptions Match{};
        CarrierOptions Options{};
    };
}
