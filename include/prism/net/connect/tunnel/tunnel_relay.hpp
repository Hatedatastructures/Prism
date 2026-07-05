/**
 * @file tunnel_relay.hpp
 * @brief 隧道转发器类（对应 mihomo Tunnel.process pipe）
 */

#pragma once

#include <prism/net/connect/tunnel/tunnel.hpp>

#include <boost/asio.hpp>

namespace psm::connect
{

    namespace net = boost::asio;

    /**
     * @class tunnel_relay
     * @brief 双向隧道转发器
     */
    class tunnel_relay
    {
    public:
        explicit tunnel_relay(tunnel_options opts) noexcept;

        [[nodiscard]] auto run() -> net::awaitable<void>;

    private:
        tunnel_options opts_;
    };

} // namespace psm::connect
