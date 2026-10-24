/**
 * @file Restls.hpp
 * @brief Restls 客户端连接工厂与服务端会话入口。
 * @details wire 状态、认证、连接与 relay 均由 Restls 私有 owner 管理。
 */
#pragma once

#include <Prism/Protocols/Restls/Types.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace Prism::Restls
{
    struct ClientConfig final
    {
        std::string password;
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

        [[nodiscard]] auto Run(SharedTransmission Inbound, const ServerConfig &Config)
            -> Net::awaitable<Result<SharedConn>>;

    private:
        std::unique_ptr<Detail::ServerSession> Owner_;
    };

    [[nodiscard]] auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        std::span<const std::uint8_t> ServerRandom)
        -> Net::awaitable<Result<SharedConn>>;

    [[nodiscard]] auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config,
        std::span<const std::uint8_t> ServerRandom)
        -> Net::awaitable<Result<SharedConn>>;
}
