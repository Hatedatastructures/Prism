/**
 * @file Server.hpp
 * @brief Restls 稳定 server-session façade。
 * @details 会话 wire 状态由 Detail::ServerSession 独占；本句柄只拥有操作实例。
 */
#pragma once

#include <Preview/Protocols/Restls/Types.hpp>
#include <Preview/Protocols/Restls/Detail/Handshake.hpp>

#include <boost/asio/awaitable.hpp>

#include <utility>

namespace Preview::Restls
{
    /**
     * @brief 单次 Restls server relay 操作的稳定 typed 入口。
     * @details Dial callback 按值持有；Run 把 Inbound 所有权交给协议 owner。
     */
    class ServerSession final
    {
    public:
        explicit ServerSession(ServerOptions Options) : Owner_(std::move(Options)) {}
        ServerSession(const ServerSession &) = delete;
        auto operator=(const ServerSession &) -> ServerSession & = delete;

        /** @brief 完成 server handshake；Config 借用至协程完成，失败保留协议进度。 */
        [[nodiscard]] auto Run(SharedTransmission Inbound, const ServerConfig &Config)
            -> Net::awaitable<Result<SharedConn>>
        {
            auto Outcome = co_await Owner_.Run(std::move(Inbound), Config);
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