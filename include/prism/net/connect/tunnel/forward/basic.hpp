/**
 * @file forward.hpp
 * @brief 正向代理转发
 * @details 组合 dial + tunnel 操作，提供完整的 TCP 隧道转发流程。
 *          签名瘦身后：forward(session_resources& res, forward_options opts)。
 */
#pragma once

#include <prism/resource/session.hpp>
#include <prism/net/connect/target.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/trace/context.hpp>

#include <boost/asio.hpp>


namespace psm::connect
{

    namespace net = boost::asio;
    using shared_transmission = transport::shared_transmission;

    /**
     * @struct forward_options
     * @brief 正向代理转发选项
     */
    struct forward_options
    {
        std::string_view label;                             ///< 协议标签
        const psm::connect::target &target;                     ///< 目标地址
        shared_transmission inbound;                        ///< 入站传输
        std::shared_ptr<trace::trace_context> trace;        ///< 日志前缀

        forward_options(std::string_view l, const psm::connect::target &t,
                        shared_transmission in)
            : label(l), target(t), inbound(std::move(in))
        {
        }

        forward_options(std::string_view l, const psm::connect::target &t,
                        shared_transmission in,
                        std::shared_ptr<trace::trace_context> tr)
            : label(l), target(t), inbound(std::move(in)), trace(std::move(tr))
        {
        }

        forward_options() = delete;
    };

    /**
     * @brief 拨号连接上游并建立双向隧道
     */
    auto forward(psm::resource::session &res, forward_options opts) -> net::awaitable<void>;

} // namespace psm::connect
