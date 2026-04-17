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
#include <prism/channel/transport/transmission.hpp>
#include <prism/memory/pool.hpp>

namespace psm::resolve
{
    class router;
}

namespace psm::multiplex
{
    namespace net = boost::asio;

    /**
     * @brief 引导多路复用会话（sing-mux 协商 + 协议分流）
     * @param transport 已建立的传输层连接
     * @param router 路由器引用，用于解析地址并连接目标
     * @param cfg 多路复用配置
     * @param mr 内存资源，为空时使用默认资源
     * @return mux 会话实例的共享指针，协商失败时返回 nullptr
     * @details 内部执行 sing-mux 协商，根据客户端 Protocol 字段
     * 选择 smux 或 yamux 协议创建对应实例。调用者通过 core 基类
     * 指针操作，无需关心具体协议类型。
     */
    [[nodiscard]] auto bootstrap(channel::transport::shared_transmission transport, resolve::router &router,
                                 const config &cfg, memory::resource_pointer mr = memory::current_resource())
        -> net::awaitable<std::shared_ptr<core>>;

} // namespace psm::multiplex
