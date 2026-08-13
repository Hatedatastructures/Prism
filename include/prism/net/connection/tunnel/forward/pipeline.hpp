/**
 * @file forward_pipeline.hpp
 * @brief 转发流水线统一入口
 */
#pragma once

#include <prism/diagnose/context.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/net/connection/target.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/resource/session.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <memory>

namespace psm::connect
{
    namespace net = boost::asio;

    /**
     * @struct pipeline_options
     * @brief 转发流水线选项
     */
    struct pipeline_options
    {
        transport::shared_transmission inbound;        // 入站传输对象
        std::shared_ptr<diagnose::context> trace;      // 日志上下文

        /**
         * @brief 构造转发流水线选项
         * @param in 入站传输对象
         * @param tr 日志上下文
         */
        explicit pipeline_options(transport::shared_transmission in, std::shared_ptr<diagnose::context> tr)
            : inbound(std::move(in)), trace(std::move(tr))
        {
        }

        pipeline_options() = delete;
    };

    /**
     * @struct pipeline_stats
     * @brief 转发流水线统计
     */
    struct pipeline_stats
    {
        std::uint64_t total{0};          // 总转发数
        std::uint64_t mux_sessions{0};   // 多路复用会话数
        std::uint64_t tcp_tunnels{0};    // TCP 隧道数
        std::uint64_t udp_associates{0}; // UDP 关联数
        std::uint64_t failed{0};         // 失败数
    };

    /**
     * @brief 完整转发流水线
     * @details 按目标协议分发到多路复用、TCP 隧道或 UDP 转发路径。
     * @param res 会话资源引用
     * @param target 转发目标（主机 + 端口 + 路由策略）
     * @param opts 转发流水线选项（入站传输、日志上下文）
     * @return 转发结束时的结果码
     */
    [[nodiscard]] auto forward_pipeline(psm::resource::session &res, const psm::connect::target &target,
                                        pipeline_options opts) -> net::awaitable<fault::code>;

    /**
     * @struct mux_session_options
     * @brief 多路复用会话启动选项
     */
    struct mux_session_options
    {
        psm::resource::session &res; // 会话资源引用
        transport::shared_transmission transport; // 承载多路复用的传输对象
        std::shared_ptr<diagnose::context> trace; // 日志上下文

        /**
         * @brief 构造多路复用会话选项
         * @param r 会话资源引用
         * @param t 承载多路复用的传输对象
         * @param tr 日志上下文
         */
        explicit mux_session_options(psm::resource::session &r, transport::shared_transmission t,
                                     std::shared_ptr<diagnose::context> tr)
            : res(r), transport(std::move(t)), trace(std::move(tr))
        {
        }

        mux_session_options() = delete;
    };

    /**
     * @brief 启动多路复用会话
     * @details 在传输对象上建立 mux 会话并转入会话协程。
     * @param opts 多路复用会话选项
     * @return 会话启动是否成功
     */
    [[nodiscard]] auto spawn_mux_session(mux_session_options opts) -> net::awaitable<bool>;

} // namespace psm::connect
