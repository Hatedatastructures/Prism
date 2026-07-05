/**
 * @file flow_opts.hpp
 * @brief opts/context 基类
 * @details 所有 dial_options / forward_options / tunnel_options /
 * stealth_opts / handler_params / bootstrap_context 继承此类，
 * 统一持有 meta/trace/cfg/outbound 四个通用字段。
 *
 * 继承方式：struct 继承。子类通过构造后字段赋值初始化。
 *
 * 字段语义：
 * - meta/trace：shared_ptr 管理，IOCP 回调保活
 * - cfg：只读配置快照，worker 生命周期
 * - outbound：出站代理接口指针，worker 生命周期（替代原 router*）
 *   通过接口访问出站能力，隐藏 worker 内部 router 资源
 */
#pragma once

#include <prism/context/metadata.hpp>

#include <memory>

namespace psm
{

    struct config;

}

namespace psm::outbound
{

    class proxy;

}

namespace psm::trace
{

    struct trace_context;

}

namespace psm::context
{

    /**
     * @struct flow_opts
     * @brief opts/context 基类，聚合通用字段
     * @details 所有 dial_options / forward_options / tunnel_options /
     * stealth_opts / handler_params / bootstrap_context 继承此类，
     * 统一持有 meta/trace/cfg/outbound 四个通用字段。
     *
     * 字段生命周期：
     * - meta/trace：shared_ptr 共享所有权，detached 协程安全
     * - cfg：非拥有裸指针，worker 生命周期保证
     * - outbound：非拥有裸指针，worker 生命周期保证（worker 构造时创建 outbound::direct）
     */
    struct flow_opts
    {
        std::shared_ptr<request_metadata> meta;        ///< 业务数据
        std::shared_ptr<trace::trace_context> trace;   ///< 日志标签
        const psm::config *cfg{nullptr};               ///< 配置快照（非拥有，worker 生命周期）
        outbound::proxy *outbound{nullptr};            ///< 出站接口（非拥有，worker 生命周期）

        flow_opts() = default;
        flow_opts(std::shared_ptr<request_metadata> m,
                  std::shared_ptr<trace::trace_context> t,
                  const psm::config *c,
                  outbound::proxy *o)
            : meta(std::move(m)), trace(std::move(t)), cfg(c), outbound(o) {}
    };

} // namespace psm::context
