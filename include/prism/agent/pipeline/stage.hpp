/**
 * @file stage.hpp
 * @brief 协议处理阶段接口
 * @details 定义 protocol_stage 抽象基类，每个 Stage 代表一种
 * 协议处理/伪装方案（如 Reality、ShadowTLS、Standard TLS）。
 * Stage Chain 按顺序执行 Stage，直到某个 Stage 返回 success。
 * 新增伪装方案只需实现新的 Stage 子类，无需修改 session 代码。
 */
#pragma once

#include <boost/asio.hpp>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>

#include <prism/agent/config.hpp>
#include <prism/agent/context.hpp>
#include <prism/protocol/probe.hpp>
#include <prism/memory/container.hpp>
#include <prism/channel/transport/transmission.hpp>

namespace psm::agent::pipeline
{
    namespace net = boost::asio;
    using shared_transmission = channel::transport::shared_transmission;

    /**
     * @enum stage_result_type
     * @brief Stage 执行结果类型
     */
    enum class stage_result_type
    {
        /** Stage 不适用此流量，调用方应尝试下一个 Stage */
        not_applicable,
        /** Stage 处理成功，已更新 ctx.inbound + detect_result */
        success,
        /** Stage 处理失败（握手错误等），连接应关闭 */
        failed,
        /** Stage 已完成透明代理到目标（如 Reality fallback），会话结束 */
        fallback_complete
    };

    /**
     * @struct stage_result
     * @brief Stage 执行返回结果
     */
    struct stage_result
    {
        stage_result_type type{stage_result_type::failed};
        shared_transmission outbound_inbound;
        protocol::protocol_type detected_protocol{protocol::protocol_type::unknown};
        memory::vector<std::byte> preread_data;
        std::error_code error;
    };

    /**
     * @class protocol_stage
     * @brief 协议处理阶段抽象接口
     */
    class protocol_stage
    {
    public:
        virtual ~protocol_stage() = default;

        /**
         * @brief 判断此 Stage 是否适用于当前流量
         * @param cfg 服务器配置
         * @return true 如果适用
         */
        [[nodiscard]] virtual auto applicable(const agent::config &cfg) const noexcept -> bool = 0;

        /**
         * @brief 执行 Stage 处理
         * @param ctx 会话上下文
         * @param detect_result 探测结果（会被 Stage 修改）
         * @param span 预读数据 span（会被 Stage 修改）
         * @return Stage 执行结果
         */
        [[nodiscard]] virtual auto process(agent::session_context &ctx, protocol::detection_result &detect_result,
                                           std::span<const std::byte> &span)
            -> net::awaitable<stage_result> = 0;

        /**
         * @brief Stage 名称（用于日志）
         */
        [[nodiscard]] virtual auto name() const noexcept -> std::string_view = 0;
    };

    using shared_stage = std::shared_ptr<protocol_stage>;
} // namespace psm::agent::pipeline
