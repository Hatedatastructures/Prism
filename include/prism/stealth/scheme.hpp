/**
 * @file scheme.hpp
 * @brief Stealth 模块伪装方案基类
 * @details 定义 stealth_scheme 抽象基类，每个方案代表一种传输层伪装方式
 * （如 Reality、ShadowTLS、Standard TLS）。调用方通过 execute() 接口
 * 完成握手和协议检测，获得最终传输层和检测到的协议类型。
 * 新增伪装方案只需继承基类并实现虚函数，无需修改 session 代码。
 */
#pragma once

#include <boost/asio.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

#include <prism/channel/transport/transmission.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/analysis.hpp>

namespace psm::resolve
{
    class router;
} // namespace psm::resolve

namespace psm
{
    struct config;
} // namespace psm

namespace psm::agent
{
    struct session_context;
} // namespace psm::agent

namespace psm::stealth
{
    namespace net = boost::asio;
    using shared_transmission = channel::transport::shared_transmission;

    /**
     * @struct scheme_result
     * @brief 伪装方案执行结果
     * @details 包含执行后的传输层、检测到的内层协议和预读数据
     */
    struct scheme_result
    {
        shared_transmission transport;            // 最终传输层
        protocol::protocol_type detected;         // 检测到的内层协议
        memory::vector<std::byte> preread;        // 内层预读数据
        fault::code error = fault::code::success; // 错误码
        memory::string executed_scheme;           // 成功执行的方案名
    };

    /**
     * @struct scheme_context
     * @brief 伪装方案执行上下文
     * @details 封装 execute() 所需的所有参数，避免参数过长。
     * 调用方应在调用前用 preview 包装 inbound（如有预读数据）。
     */
    struct scheme_context
    {
        shared_transmission inbound;              // 当前传输层（应包含预读数据）
        const psm::config *cfg{nullptr};          // 服务器配置
        resolve::router *router{nullptr};         // 路由器（fallback 用）
        agent::session_context *session{nullptr}; // 会话上下文
    };

    /**
     * @class stealth_scheme
     * @brief 传输层伪装方案抽象基类
     */
    class stealth_scheme
    {
    public:
        virtual ~stealth_scheme() = default;

        /**
         * @brief 判断此方案是否在当前配置下启用
         * @param cfg 服务器配置
         * @return true 如果启用
         */
        [[nodiscard]] virtual auto is_enabled(const psm::config &cfg) const noexcept -> bool = 0;

        /**
         * @brief 执行方案处理
         * @param ctx 执行上下文（传输层、预读数据、配置、路由器、会话）
         * @return 处理结果
         */
        [[nodiscard]] virtual auto execute(scheme_context ctx)
            -> net::awaitable<scheme_result> = 0;

        /**
         * @brief 方案名称（用于日志）
         */
        [[nodiscard]] virtual auto name() const noexcept -> std::string_view = 0;
    };

    using shared_scheme = std::shared_ptr<stealth_scheme>;

} // namespace psm::stealth
