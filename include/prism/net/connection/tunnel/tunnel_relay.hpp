/**
 * @file tunnel_relay.hpp
 * @brief 隧道转发器类（对应 mihomo Tunnel.process pipe）
 */

#pragma once

#include <prism/net/connection/tunnel/tunnel.hpp>

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
        /**
         * @brief 构造双向隧道转发器
         * @param opts 隧道选项（入站/出站流、写入策略等）
         */
        explicit tunnel_relay(tunnel_options opts) noexcept;

        /**
         * @brief 运行双向隧道转发
         * @details 启动双向数据转发，任一方向断开即终止整个隧道。
         * @return 协程对象，隧道结束后完成
         */
        [[nodiscard]] auto run() -> net::awaitable<void>;

    private:
        tunnel_options opts_; // 隧道选项
    };

} // namespace psm::connect
