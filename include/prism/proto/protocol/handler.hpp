/**
 * @file handler.hpp
 * @brief 协议处理器抽象基类 + 工厂
 * @details 定义统一的协议处理器接口，消除 session::diversion 中的 switch-case。
 * 每种协议（HTTP/SOCKS5/Trojan/VLESS/SS2022）实现 handler 子类，
 * 由工厂函数 make_protocol_handler 创建。
 *
 * 设计参照 mihomo Proxy interface：
 *   - 虚基类 protocol_handler 定义统一接口（run()）
 *   - 工厂函数按 protocol_type 创建具体子类
 *   - session::diversion 只调 make_protocol_handler + run，不 switch
 *
 * @note 过渡期：工厂内部用 legacy_handler 包装旧的 free function handle()，
 * Phase 2 逐个替换成具体 handler 子类。
 */

#pragma once

#include <prism/context/flow_opts.hpp>
#include <prism/proto/protocol/types.hpp>

#include <boost/asio.hpp>

#include <cstddef>
#include <memory>
#include <span>

namespace psm::context { struct session; }

namespace psm::protocol
{

    namespace net = boost::asio;

    /**
     * @class protocol_handler
     * @brief 协议处理器抽象基类
     * @details 所有协议处理器实现此接口。run() 执行完整的协议处理流程
     *（握手 → 解析目标 → 拨号 → 隧道转发），由 session::diversion 统一调用。
     */
    class protocol_handler
    {
    public:
        virtual ~protocol_handler() noexcept = default;

        /**
         * @brief 执行协议处理
         * @return 协程对象，协议处理完成后完成
         */
        virtual auto run() -> net::awaitable<void> = 0;
    };

    /**
     * @struct handler_params
     * @brief 协议处理器构造参数
     * @details 继承 flow_opts 获取 meta/trace/cfg/rt 通用字段，
     * 添加 ctx（会话引用）和 data（预读数据）。
     */
    struct handler_params : public psm::context::flow_opts
    {
        context::session& ctx;                       ///< 会话上下文
        std::span<const std::byte> data;             ///< 预读数据

        explicit handler_params(context::session& s, std::span<const std::byte> d)
            : ctx(s), data(d) {}
    };

    /**
     * @brief 创建协议处理器
     * @param type 识别出的协议类型
     * @param params 构造参数（ctx + data + prefix）
     * @return 协议处理器实例，unknown 类型返回 nullptr
     */
    [[nodiscard]] auto make_protocol_handler(
        protocol_type type, handler_params params
    ) -> std::unique_ptr<protocol_handler>;

} // namespace psm::protocol
