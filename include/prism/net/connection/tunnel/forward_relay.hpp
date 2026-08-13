/**
 * @file forward_relay.hpp
 * @brief 正向代理转发器类
 */

#pragma once

#include <prism/net/connection/tunnel/forward/basic.hpp>

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
        /**
         * @brief 构造正向代理转发器
         * @param res 会话资源引用
         * @param opts 转发选项
         */
        forward_relay(psm::resource::session &res, forward_options opts) noexcept;

        /**
         * @brief 运行正向代理转发
         * @details 启动完整的正向代理转发流水线，直到隧道结束。
         * @return 协程对象，转发结束后完成
         */
        [[nodiscard]] auto run() -> net::awaitable<void>;

    private:
        psm::resource::session &res_; // 会话资源引用
        forward_options opts_;        // 转发选项
    };

} // namespace psm::connect
