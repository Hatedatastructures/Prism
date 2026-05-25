/**
 * @file bootstrap.hpp
 * @brief 多路复用会话引导（sing-mux 协商 + 协议分流）
 * @details 多路复用会话的统一入口，完成 sing-mux 协议协商后根据客户端
 * 选择的协议类型创建对应的 core 子类实例。协商基本格式（Version==0）：
 * [Version 1B][Protocol 1B]，扩展格式（Version>0）：
 * [Version 1B][Protocol 1B][PaddingLen 2B BE][Padding N bytes]。
 * Protocol 字段指示客户端选择的多路复用协议类型（0=smux, 1=yamux）。
 * 协商完成后，transport 上的后续数据由具体 mux 协议帧解释。
 */

#pragma once

#include <memory>

#include <boost/asio.hpp>

#include <prism/multiplex/config.hpp>
#include <prism/multiplex/core.hpp>
#include <prism/transport/transmission.hpp>
#include <prism/memory/pool.hpp>
#include <prism/protocol/types.hpp>

namespace psm::connect
{
    class router;
}

namespace psm::stats::traffic
{
    class traffic_state;
}

namespace psm::multiplex
{
    namespace net = boost::asio;

    /**
     * @struct bootstrap_context
     * @brief 多路复用会话引导上下文
     * @details 聚合 bootstrap 所需的所有参数，避免函数参数超过 3 个。
     * 调用者通过聚合初始化填充各字段。
     */
    struct bootstrap_context
    {
        transport::shared_transmission transport;                   ///< 已建立的传输层连接
        connect::router &router;                                    ///< 路由器引用，用于解析地址并连接目标
        const config &cfg;                                          ///< 多路复用配置
        memory::resource_pointer mr{};                              ///< PMR 内存资源，为空时使用默认资源
        stats::traffic::traffic_state *traffic{nullptr};            ///< per-worker 流量统计指针
        protocol::protocol_type proto{protocol::protocol_type::unknown}; ///< 归属的外层协议类型
    };

    /**
     * @brief 引导多路复用会话（sing-mux 协商 + 协议分流）
     * @param ctx 引导上下文，包含传输层、路由器、配置、内存资源和流量统计参数
     * @return mux 会话实例的共享指针，协商失败时返回 nullptr
     * @details 内部执行 sing-mux 协商，根据客户端 Protocol 字段
     * 选择 smux 或 yamux 协议创建对应实例。调用者通过 core 基类
     * 指针操作，无需关心具体协议类型。
     */
    [[nodiscard]] auto bootstrap(bootstrap_context ctx)
        -> net::awaitable<std::shared_ptr<core>>;

} // namespace psm::multiplex
