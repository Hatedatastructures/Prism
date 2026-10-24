/**
 * @file SessionOptions.hpp
 * @brief 多路复用会话的公共选项。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>

#include <chrono>
#include <cstddef>
#include <memory>

namespace Prism::Mux
{
    /** @brief 多路复用连接角色；决定流 ID 奇偶。 */
    enum class Role
    {
        /// 服务端接收对端握手并分配偶数流 ID。
        Server,
        /// 客户端主动发起握手并分配奇数流 ID。
        Client,
    };

    /**
     * @struct SessionOptions
     * @brief 多路复用会话选项。
     * @details 构造后只读，经 Session::Create 传入。
     */
    struct SessionOptions
    {
        /// 协议拥有的 engine scope；未绑定父 scope 时建立独立 registry，帧和 writer 始终追踪。
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Registry{};
        /// listener 提交的父任务身份；Mux 子任务只重新分配 TaskId。
        Prism::Lifecycle::TaskIdentity Identity{};
        /// 连接角色（决定流 ID 奇偶：Client 奇数 / Server 偶数）。
        Prism::Mux::Role Role{Prism::Mux::Role::Client};
        /// 最大并发流数。
        std::size_t MaxStreams{256};
        /// 读超时（0 = 禁用）。
        std::chrono::milliseconds timeout{0};
        /// 每流接收队列字节预算（0 = 不限）；超限关闭会话。
        std::size_t MaxStreamRxBytes{4 * 1024 * 1024};
        /// 会话接收队列总字节预算（0 = 不限）；超限关闭会话。
        std::size_t MaxSessionRxBytes{16 * 1024 * 1024};
        /// 待发送帧总字节预算（0 = 不限）；超限只拒绝本次写入。
        std::size_t MaxPendingWriteBytes{32 * 1024 * 1024};
        /// 会话固定的 Diagnose epoch；服务器显式继承其入站 generation。
        Prism::Diagnose::ContextState Trace{Prism::Diagnose::CaptureCurrentContext()};
    };
} // namespace Prism::Mux
