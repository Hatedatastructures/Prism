/**
 * @file scheme.hpp
 * @brief Stealth 模块伪装方案基类
 * @details 定义 stealth_scheme 抽象基类，每个方案代表一种传输层伪装方式
 * （如 Reality、ShadowTLS、Standard TLS）。调用方通过 handshake() 接口
 * 完成握手和协议检测，获得最终传输层和检测到的协议类型。
 *
 * 分层检测架构：
 * SNI 路由（scheme_route_table）确定候选方案
 * Tier 0: sniff() - 零成本字节比较（Reality session_id 标记）
 * Tier 1: verify() - 有成本验证（ShadowTLS HMAC）
 * Tier 2: guess() - 模糊匹配（Restls/TrustTunnel）
 * handshake() 执行握手，失败则 fallback 到真实 TLS
 */
#pragma once

#include <prism/core/fault/code.hpp>
#include <prism/core/memory/container.hpp>
#include <prism/proto/protocol/tls/types.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/stealth/recognition/tls/features.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>


namespace psm::connect
{

    class router;
} // namespace psm::connect

namespace psm
{

    struct config;
} // namespace psm

namespace psm::context
{

    struct session;
} // namespace psm::context

namespace psm::stealth
{

    namespace net = boost::asio;
    using shared_transmission = transport::shared_transmission;
    using hello_features = protocol::tls::hello_features;

    /**
     * @enum scheme_category
     * @brief 方案执行分类
     * @details facade 方案返回 transport + preread，executor 做二次探测；
     * stack 方案内部管理流不返回 transport，executor 收到即终止。
     */
    enum class scheme_category : std::uint8_t
    {
        facade, ///< 返回 transport + preread，executor 做二次探测
        stack   ///< 内部管理流，executor 收到即终止
    };

    // 快速检测结果（Tier 0）

    /**
     * @struct sniff_result
     * @brief Tier 0 快速检测结果
     * @details 零成本字节比较，返回是否命中和是否独占。
     */
    struct sniff_result
    {
        /** @brief 是否命中此方案 */
        bool hit{false};

        /** @brief 是否独占命中（命中则不再检测其他方案） */
        bool solo{false};

        /** @brief 评分提示（供 Tier 2 参考，范围 0-1000） */
        std::uint16_t hint{0};

        /** @brief 检测原因（用于日志和调试） */
        memory::string note;
    };

    // 详细检测结果（Tier 1）

    /**
     * @struct verify_result
     * @brief 伪装方案检测结果（评分制）
     * @details 使用评分制，支持优先级排序。
     * solo_flag 非零表示独占命中，不再检测其他方案。
     */
    struct verify_result
    {
        /** @brief 评分（0-1000，越高越确定） */
        std::uint16_t score{0};

        /** @brief 独占标记（非零表示独占，跳过其他方案） */
        std::uint16_t solo_flag{0};

        /** @brief 检测原因（用于日志和调试） */
        memory::string note;
    };

    // 执行结果和上下文

    /**
     * @struct handshake_result
     * @brief 伪装方案执行结果
     * @details 包含执行后的传输层、检测到的内层协议和预读数据
     */
    struct handshake_result
    {
        shared_transmission transport;            ///< 最终传输层
        protocol::protocol_type detected;         ///< 检测到的内层协议
        memory::vector<std::byte> preread;        ///< 内层预读数据
        fault::code error = fault::code::success; ///< 错误码
        memory::string scheme;                    ///< 成功执行的方案名
        bool polluted{false};                     ///< 握手已向客户端写入数据但最终失败，不可 rewind
    };

    /**
     * @struct handshake_context
     * @brief 伪装方案执行上下文
     * @details 封装 handshake() 所需的所有参数，避免参数过长。
     * 调用方应在调用前用 preview 包装 inbound（如有预读数据）。
     */
    struct handshake_context
    {
        shared_transmission inbound;              ///< 当前传输层（应包含预读数据）
        const psm::config *cfg{nullptr};          ///< 服务器配置
        connect::router *router{nullptr};         ///< 路由器（fallback 用）
        context::session *session{nullptr};       ///< 会话上下文
        // session 保活：caller 必须赋值为 shared_ptr<psm::instance::session::session>。
        // 类型用 shared_ptr<void> 是为避免 stealth → instance 循环依赖（stealth 模块
        // 不能直接引用 instance::session::session 类型）。运行时 shared_ptr<void> 通过
        // aliasing constructor 正确持有引用计数，功能等价 shared_ptr<session>。
        // 详见 docs/ARCHITECTURE.md "anytls scheme.cpp 的 detached task"。
        // 注意：detached task 捕获此字段时必须真正持有它（move 进 lambda），
        // 否则 session 会在 task 期间析构，导致 session_ptr 悬垂。
        std::shared_ptr<void> session_keepalive;
        memory::vector<std::byte> preread;        ///< 来自 identify 的 preread 数据（完整 ClientHello）
    };

    // 方案基类

    /**
     * @class stealth_scheme
     * @brief 传输层伪装方案抽象基类
     * @details 支持分层检测：
     * Tier 0: sniff() - 零成本字节比较
     * Tier 1: verify() - 有成本验证（HMAC/解密）
     * Tier 2: guess() - 模糊匹配（SNI 路由）
     * handshake() 执行握手，失败则 fallback 到真实 TLS
     */
    class stealth_scheme
    {
    public:
        virtual ~stealth_scheme() noexcept = default;

        // === 身份 ===

        /// 方案名称（用于日志）
        [[nodiscard]] virtual auto name() const noexcept
            -> std::string_view = 0;

        /// 检测层级（0-2），Tier 0 有独占特征，Tier 2 依赖 SNI
        [[nodiscard]] virtual auto tier() const noexcept
            -> std::uint8_t
        {
            return 2; // 默认 Tier 2（模糊）
        }

        /// 是否有独占特征（命中时跳过其他方案）
        [[nodiscard]] virtual auto unique() const noexcept
            -> bool
        {
            return false; // 默认无独占特征
        }

        /// 方案执行分类（facade 返回 transport，stack 内部管理流）
        [[nodiscard]] virtual auto category() const noexcept
            -> scheme_category
        {
            return scheme_category::facade;
        }

        // === 配置 ===

        /// 判断此方案是否在当前配置下启用
        [[nodiscard]] virtual auto active(const psm::config &cfg) const noexcept
            -> bool = 0;

        /// 获取 SNI 白名单
        [[nodiscard]] virtual auto snis(const psm::config & /*cfg*/) const
            -> memory::vector<memory::string>
        {
            return {}; // 默认无 SNI 白名单
        }

        // === Tier 0: 快速检测（零成本）===

        /**
         * @brief 快速检测（零成本，Tier 0）
         * @param bitmap 特征位图
         * @param features ClientHello 特征结构
         * @return 快速检测结果
         * @details 只做字节比较，不涉及 HMAC 或解密。
         * 例如 Reality 检查 session_id[0:3] == [0x01, 0x08, 0x02]。
         */
        [[nodiscard]] virtual auto sniff(std::uint32_t /*bitmap*/, const hello_features & /*features*/) const
            -> sniff_result
        {
            // 默认：不支持快速检测
            return {.hit = false, .solo = false, .hint = 0, .note = "no sniff"};
        }

        // === Tier 1: 详细检测（有成本）===

        /**
         * @brief 详细检测（有成本，Tier 1）
         * @param features ClientHello 特征结构
         * @param raw 原始 ClientHello 字节
         * @param cfg 服务器配置
         * @return 详细检测结果
         * @details 涉及 HMAC 验证或解密，延迟执行。
         * 例如 ShadowTLS HMAC 验证、AnyTLS ECH 解密。
         */
        [[nodiscard]] virtual auto verify(const hello_features & /*features*/, std::span<const std::byte> /*raw*/, const psm::config & /*cfg*/) const
            -> verify_result
        {
            // 默认：不支持详细检测
            return {.score = 0, .solo_flag = 0, .note = "no verify"};
        }

        // === Tier 2: 模糊检测（兜底）===

        /**
         * @brief 模糊检测（Tier 2）
         * @param cfg 服务器配置
         * @return 模糊检测结果
         * @details 无 ClientHello 独占特征，依赖 SNI 匹配。
         * 例如 Restls、TrustTunnel、Native。
         */
        [[nodiscard]] virtual auto guess(const psm::config & /*cfg*/) const
            -> verify_result
        {
            // 默认：返回权重分
            return {.score = weight(), .solo_flag = 0, .note = "guess"};
        }

        // === 执行 ===

        /**
         * @brief 执行握手
         * @param ctx 执行上下文（传输层、预读数据、配置、路由器、会话）
         * @return 处理结果
         */
        [[nodiscard]] virtual auto handshake(handshake_context ctx)
            -> net::awaitable<handshake_result> = 0;

    protected:
        /// 权重分（Tier 2 使用）
        [[nodiscard]] virtual auto weight() const noexcept
            -> std::uint16_t
        {
            return 100;
        }

        /// 辅助方法：将任意范围的字符串转换为 SNI 白名单
        template <typename StringRange>
        [[nodiscard]] static auto make_sni_list(const StringRange &names)
            -> memory::vector<memory::string>
        {
            memory::vector<memory::string> result;
            for (const auto &name : names)
                result.push_back(memory::string(name));
            return result;
        }
    };

    using shared_scheme = std::shared_ptr<stealth_scheme>;

} // namespace psm::stealth