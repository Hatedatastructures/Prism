/**
 * @file forward_relay.hpp
 * @brief 正向代理转发器类
 */

#pragma once

#include <prism/net/connect/tunnel/forward/basic.hpp>

#include <boost/asio.hpp>

namespace psm::connect
{

    namespace net = boost::asio;

    /**
     * @class forward_relay
     * @brief 正向代理转发器（组合 dialer + tunnel_relay）
     */
    class forward_relay
    {
    public:
        forward_relay(psm::resource::session &res, forward_options opts) noexcept;

        [[nodiscard]] auto run() -> net::awaitable<void>;

    private:
        psm::resource::session &res_;
        forward_options opts_;
    };

} // namespace psm::connect
