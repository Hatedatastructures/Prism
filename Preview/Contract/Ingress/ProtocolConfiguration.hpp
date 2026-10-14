/** @file ProtocolConfiguration.hpp @brief 编译前协议实例与承载绑定的唯一配置值。 */
#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
namespace Preview::Contract
{
    struct ProtocolConfiguration final
    {
        std::string Id,Name,Builtin;
        std::vector<std::string> Requires;
        struct QuicOptions final
        {
            std::string Alpn{"h3"},ServerName,CredentialSecretRef;
            std::uint32_t MaxStreams{64},MaxDatagrams{64};
            std::string Uuid;
        };
        std::optional<QuicOptions> Quic;
    };
    struct RecognitionRouteConfiguration final
    {
        std::string Pattern;
        bool Fallback{false};
    };
    struct ProtocolBindingConfiguration final
    {
        std::string Id,ProtocolId;
        std::optional<std::string> CarrierId;
        bool TcpEnabled{true},UdpEnabled{false};
        std::vector<std::string> MuxModes;
        std::int32_t Priority{0};
        RecognitionRouteConfiguration Recognition{};
    };
}
