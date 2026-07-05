/**
 * @file forward.hpp
 * @brief 正向代理转发
 * @details 组合 dial + tunnel 操作，提供完整的 TCP 隧道转发流程。
 */
#pragma once

#include <prism/context/context.hpp>
#include <prism/context/flow_opts.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>


namespace psm::connect
{

    namespace net = boost::asio;
    using shared_transmission = transport::shared_transmission;

    /**
     * @struct forward_options
     * @brief 正向代理转发选项
     * @details 组合拨号+隧道转发所需的全部参数。
     * 继承 flow_opts 持有 meta/trace/cfg/rt 通用字段。为兼容旧调用方，
     * 保留 `prefix` 字段（deprecated），构造函数同步初始化 flow_opts::trace。
     */
    struct forward_options : public psm::context::flow_opts
    {
        std::string_view label;               ///< 协议标签，用于日志记录
        const protocol::target &target;       ///< 目标地址信息
        shared_transmission inbound;          ///< 入站传输对象

        /// @deprecated 改用 flow_opts::trace（P10 删除）
        std::shared_ptr<trace::trace_context> prefix;

        /// 兼容旧 3 参聚合初始化：{label, target, inbound}（prefix 默认空）
        forward_options(std::string_view l, const protocol::target &t,
                        shared_transmission in)
            : label(l), target(t), inbound(std::move(in))
        {
        }

        /// 兼容旧 4 参聚合初始化：{label, target, inbound, prefix}
        forward_options(std::string_view l, const protocol::target &t,
                        shared_transmission in,
                        std::shared_ptr<trace::trace_context> p)
            : label(l), target(t), inbound(std::move(in)), prefix(std::move(p))
        {
            this->trace = prefix;
        }

        /// 完整构造（新代码推荐）
        forward_options(std::string_view l, const protocol::target &t,
                        shared_transmission in,
                        std::shared_ptr<psm::context::request_metadata> m,
                        std::shared_ptr<trace::trace_context> tc)
            : psm::context::flow_opts(std::move(m), std::move(tc), nullptr, nullptr),
              label(l), target(t), inbound(std::move(in))
        {
            this->prefix = this->trace;
        }

        forward_options() = delete;
    };

    /**
     * @brief 拨号连接上游并建立双向隧道
     * @param ctx 会话上下文，提供路由器和会话信息
     * @param opts 转发选项（标签、目标、入站传输）
     * @return 协程对象，隧道结束后完成
     * @details 组合 dial + tunnel 操作，所有协议的 TCP 隧道转发共用此函数。
     * 先通过路由器建立到目标的上游连接，连接成功后进入双向隧道转发。
     */
    auto forward(context::session &ctx, forward_options opts) -> net::awaitable<void>;

} // namespace psm::connect
