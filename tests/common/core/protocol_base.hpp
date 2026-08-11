/**
 * @file protocol_base.hpp
 * @brief 协议端点抽象基类（客户端 / 服务端统一骨架）
 * @details 借鉴 Boost.Beast 组合操作（composed operations）与模板方法模式：
 *          - client_base / server_base 定义握手流程骨架（模板方法）
 *          - 派生协议通过 override 握手各阶段（写请求 / 读响应 / 认证）
 *          - 上层通过基类指针切换协议（多态），热路径保持虚调用
 *          - 握手阶段返回 session_base（统一数据通道）
 * @note 纯虚接口：协议实现必须提供连接 / 监听 / 握手 / 会话构造。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/stream.hpp>
#include <common/core/transport/transport_base.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace psmtest
{

    /// 目标地址（协议统一使用）
    struct address
    {
        /// 地址类型
        enum class type : std::uint8_t
        {
            /// IPv4
            ipv4 = 1,
            /// IPv6
            ipv6 = 2,
            /// 域名
            domain = 3,
        };

        type addr_type{type::domain};
        std::string host;
        std::uint16_t port{0};

        /// IPv4 地址（addr_type == ipv4 时）
        std::array<std::uint8_t, 4> ipv4{};
        /// IPv6 地址（addr_type == ipv6 时）
        std::array<std::uint8_t, 16> ipv6{};
    };

    /// 客户端端点抽象基类
    class client_base
    {
    public:
        virtual ~client_base() = default;

        /// @brief 建立连接并完成握手（客户端视角）
        /// @param raw 底层传输流（类型擦除）
        /// @param target 目标地址
        /// @param timeout 握手超时
        /// @return 数据会话；nullptr = 握手失败
        virtual auto connect(transport_base &raw, const address &target,
                             std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<std::shared_ptr<session_base>>
            = 0;

        /// 获取执行器
        [[nodiscard]] virtual auto executor() const -> net::any_io_executor = 0;
    };

    /// 服务端端点抽象基类
    class server_base
    {
    public:
        virtual ~server_base() = default;

        /// @brief 接收连接并完成握手（服务端视角）
        /// @param raw 底层传输流（类型擦除）
        /// @param target 输出参数：客户端请求的目标地址
        /// @param timeout 握手超时
        /// @return 数据会话；nullptr = 握手失败
        virtual auto accept(transport_base &raw, address &target,
                            std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<std::shared_ptr<session_base>>
            = 0;

        /// 获取执行器
        [[nodiscard]] virtual auto executor() const -> net::any_io_executor = 0;
    };

} // namespace psmtest
