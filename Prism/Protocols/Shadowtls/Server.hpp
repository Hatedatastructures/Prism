/**
 * @file Server.hpp
 * @brief ShadowTLS 稳定的 server-session façade。
 * @details 完整 relay 状态由 Detail::ServerSession 独占管理。
 */
#pragma once

#include <Prism/Protocols/Shadowtls/Types.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Handshake.hpp>

#include <boost/asio/awaitable.hpp>

#include <utility>

namespace Prism::Shadowtls
{
    /**
     * @brief 单次 ShadowTLS server relay 操作的稳定 typed 入口。
     * @details DialTarget 按值持有；Run 把入站传输交给 Detail owner。
     */
    class ServerSession final
    {
    public:
        explicit ServerSession(ServerOptions Options) : Owner_(std::move(Options)) {}
        ServerSession(const ServerSession &) = delete;
        auto operator=(const ServerSession &) -> ServerSession & = delete;

        /** @brief 执行认证 relay；失败保留 Native 与 wire 进度。 */
        [[nodiscard]] auto Run(SharedTransmission Inbound, ServerConfig Config)
            -> Net::awaitable<Result<SharedConn>>
        {
            auto Outcome = co_await Owner_.Run(std::move(Inbound), std::move(Config));
            if (!Outcome)
            {
                co_return std::unexpected(Outcome.error());
            }
            co_return SharedConn(std::move(*Outcome));
        }

    private:
        Detail::ServerSession Owner_;
    };
}