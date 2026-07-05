/**
 * @file forward_pipeline.hpp
 * @brief 转发流水线统一入口
 * @details 替代协议/伪装层各自拼装 tunnel_options 的反模式。内部完成：
 *   1. mux 标记检查（is_mux + 配置开关）
 *   2. outbound::dial 拨号
 *   3. 构造 tunnel_options（内部 6 字段填装）
 *   4. 启动 tunnel_relay 或 multiplex::bootstrap
 *
 * 设计目的：
 *   - 消除 socks5/http/trojan/vless/shadowsocks 5 个 handler 中重复的
 *     tunnel_options 拼装代码（7 字段 × 5 处 = 35 行重复）
 *   - 消除 trojan/vless/anytls 3 处重复的 mux bootstrap_context 拼装
 *   - 协议 handler 回归"仅协议解析"职责
 *
 * @note 调用方必须先 lock worker::borrow 得到 handle 再传入
 */
#pragma once

#include <prism/context/context.hpp>
#include <prism/worker/resources.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/trace/context.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <memory>


namespace psm::connect
{
    namespace net = boost::asio;

    /**
     * @struct pipeline_options
     * @brief 转发流水线选项
     * @details 收敛 inbound/target/trace/mux 检查开关到单一 struct。
     */
    struct pipeline_options
    {
        transport::shared_transmission inbound;               ///< 入站传输层
        const protocol::target &target;                       ///< 目标地址
        std::shared_ptr<trace::trace_context> trace;          ///< 日志前缀
        bool enable_mux_check{true};                          ///< 是否检查 mux 标记

        /**
         * @brief 构造 pipeline_options
         * @param in 入站传输层
         * @param t 目标地址引用
         * @param tr 日志前缀
         */
        explicit pipeline_options(
            transport::shared_transmission in,
            const protocol::target &t,
            std::shared_ptr<trace::trace_context> tr)
            : inbound(std::move(in)), target(t), trace(std::move(tr))
        {
        }

        pipeline_options() = delete;
    };

    /**
     * @struct pipeline_stats
     * @brief 转发流水线累计统计
     */
    struct pipeline_stats
    {
        std::uint64_t total{0};           ///< 总流水线数
        std::uint64_t mux_sessions{0};    ///< mux 启动数
        std::uint64_t tcp_tunnels{0};     ///< TCP 隧道数
        std::uint64_t udp_associates{0};  ///< UDP 关联数
        std::uint64_t failed{0};          ///< 失败数
    };

    /**
     * @brief 完整转发流水线
     * @param handle worker 资源 handle
     * @param session 会话上下文（用于 account_lease/detected_protocol/buffer_size）
     * @param opts 流水线选项
     * @return fault::code 表示结果。success 表示正常完成或 mux 启动成功；
     *         其他表示拨号/隧道失败，调用方据此做协议特定响应（如 socks5 send_error）。
     * @details 内部流程：
     *   1. mux 标记检查（is_mux(target.host, mux_sw) && enable_mux_check）
     *   2. 命中 mux：调 spawn_mux_session 启动多路复用
     *   3. 未命中：outbound::dial → 构造 tunnel_options → tunnel_relay
     */
    [[nodiscard]] auto forward_pipeline(
        psm::worker::handle handle,
        context::session &session,
        pipeline_options opts) -> net::awaitable<fault::code>;

    /**
     * @struct mux_session_options
     * @brief mux 会话引导参数
     * @details 收敛 spawn_mux_session 的 4 参数为单一 struct（Rule 1）。
     */
    struct mux_session_options
    {
        psm::worker::handle handle;                 ///< worker 资源 handle
        context::session &session;                     ///< 会话上下文
        transport::shared_transmission transport;      ///< 已建立的传输层
        std::shared_ptr<trace::trace_context> trace;   ///< 日志前缀

        explicit mux_session_options(
            psm::worker::handle h,
            context::session &s,
            transport::shared_transmission t,
            std::shared_ptr<trace::trace_context> tr)
            : handle(std::move(h)), session(s), transport(std::move(t)), trace(std::move(tr))
        {
        }

        mux_session_options() = delete;
    };

    /**
     * @brief mux 会话引导封装
     * @param opts 引导参数（handle + session + transport + trace）
     * @return true 启动成功；false 启动失败
     * @details 替代 trojan/vless/anytls 三处重复的 bootstrap_context 拼装。
     */
    [[nodiscard]] auto spawn_mux_session(mux_session_options opts) -> net::awaitable<bool>;

} // namespace psm::connect
