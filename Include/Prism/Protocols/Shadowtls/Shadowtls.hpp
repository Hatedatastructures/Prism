/**
 * @file Shadowtls.hpp
 * @brief ShadowTLS v3 typed client factories与服务端会话入口。
 * @details 连接、record、control 和 relay 状态由协议私有 owner 管理。
 */
#pragma once

#include <Prism/Protocols/Shadowtls/Types.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace Prism::Shadowtls
{
    struct ServerHandover final
    {
        std::vector<std::uint8_t> ClientHelloWire;
        SharedConn Connection;
    };

    struct ConnectParameters final
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::span<const std::uint8_t> ServerRandom;
        std::span<const std::uint8_t> ClientRandom;
    };

    struct StandardConnectParameters final
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::span<const std::uint8_t> ClientHelloWire;
    };

    struct StandardConnectResult final
    {
        std::vector<std::uint8_t> ClientHelloWire;
        SharedConn Connection;
    };

    namespace Detail
    {
        class ServerSession;
    }

    class ServerSession final
    {
    public:
        explicit ServerSession(ServerOptions Options);
        ~ServerSession() noexcept;
        ServerSession(const ServerSession &) = delete;
        auto operator=(const ServerSession &) -> ServerSession & = delete;
        ServerSession(ServerSession &&) = delete;
        auto operator=(ServerSession &&) -> ServerSession & = delete;

        [[nodiscard]] auto Run(SharedTransmission Inbound, ServerConfig Config)
            -> Net::awaitable<Result<SharedConn>>;

    private:
        std::unique_ptr<Detail::ServerSession> Owner_;
    };

    [[nodiscard]] auto Connect(ConnectParameters Params)
        -> Net::awaitable<Result<SharedConn>>;
    [[nodiscard]] auto ConnectStandard(StandardConnectParameters Params)
        -> Net::awaitable<Result<StandardConnectResult>>;
    [[nodiscard]] auto Accept(SharedTransmission Upstream, const ServerConfig &Config)
        -> Net::awaitable<Result<SharedConn>>;
    [[nodiscard]] auto AcceptStandard(SharedTransmission Upstream, const ServerConfig &Config)
        -> Net::awaitable<Result<ServerHandover>>;
}
