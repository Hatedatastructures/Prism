/**
 * @file scheme.hpp
 * @brief Restls 伪装方案类
 * @details 实现 stealth_scheme 接口，用于在 TLS 方案管道中处理 Restls 连接。
 */
#pragma once

#include <prism/stealth/scheme.hpp>
#include <prism/stealth/restls/config.hpp>

namespace psm::stealth::restls
{
    /**
     * @class scheme
     * @brief Restls 伪装方案实现
     * @details Restls 通过模拟真实 TLS 流量来隐藏代理特征。
     * 服务端与后端 TLS 服务器建立连接，在 TLS 应用数据中嵌入认证信息。
     *
     * **工作流程**：
     * 1. 读取客户端 TLS ClientHello
     * 2. 建立到后端 TLS 服务器的连接
     * 3. 在 TLS 应用数据中验证客户端身份
     * 4. 认证成功后，使用 restls-script 控制流量模式
     */
    class scheme final : public stealth_scheme
    {
    public:
        /**
         * @brief 检查 Restls 方案是否启用
         * @param cfg 全局配置
         * @return 如果配置有效（host 和 password 非空），返回 true
         */
        [[nodiscard]] auto is_enabled(const psm::config &cfg) const noexcept
            -> bool override;
            
        [[nodiscard]] auto detect(const protocol::tls::client_hello_features &features, const psm::config &cfg) const
            -> detection_result override;

        /**
         * @brief 执行 Restls 处理
         * @param ctx 方案上下文，包含会话信息
         * @return 处理结果，包含传输层、检测到的协议和预读数据
         */
        auto execute(scheme_context ctx) -> net::awaitable<scheme_result> override;

        /**
         * @brief 获取方案名称
         * @return "restls"
         */
        [[nodiscard]] auto name() const noexcept -> std::string_view override;
    };
} // namespace psm::stealth::restls