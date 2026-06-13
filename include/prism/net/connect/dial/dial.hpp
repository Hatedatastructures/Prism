/**
 * @file dial.hpp
 * @brief 连接拨号函数
 * @details 提供 TCP dial、UDP datagram 和路由回调等自由函数。
 * 整合了原 primitives::dial 和 resolve::router 的路由逻辑。
 */
#pragma once

#include <prism/net/connect/dial/router.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/core/fault/code.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>


namespace psm::outbound
{

    class proxy;
} // namespace psm::outbound

namespace psm::connect
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using shared_transmission = transport::shared_transmission;

    /**
     * @brief 检查目标地址是否为 IPv6 字面量
     * @param host 目标主机名或 IP 地址
     * @return 如果是 IPv6 地址字面量返回 true
     */
    [[nodiscard]] inline auto is_ipv6(const std::string_view host) noexcept
        -> bool
    {
        boost::system::error_code ec;
        const auto addr = net::ip::make_address(host, ec);
        return !ec && addr.is_v6();
    }

    /**
     * @brief 从端点列表中尝试连接，最多尝试 3 个端点
     * @param router 路由器引用
     * @param endpoints 候选端点列表
     * @return 成功连接的套接字，或无效 pooled_connection
     */
    [[nodiscard]] auto retry_connect(router &rt, std::span<const tcp::endpoint> endpoints)
        -> net::awaitable<pooled_connection>;

    /**
     * @brief 异步路由直连 TCP 端点
     * @param rt 路由器引用
     * @param ep 目标 TCP 端点
     * @return 协程对象，返回结果码与 TCP 套接字的配对
     */
    [[nodiscard]] auto async_direct(router &rt, tcp::endpoint ep)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>;

    /**
     * @brief 异步路由正向代理请求
     * @details 通过 DNS 解析器进行域名解析并建立连接。
     * @param rt 路由器引用
     * @param host 目标主机名
     * @param port 目标服务端口
     * @return 协程对象，返回结果码与 TCP 套接字的配对
     */
    [[nodiscard]] auto async_forward(router &rt, std::string_view host, std::string_view port)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>;

    /**
     * @brief 异步路由数据报请求
     * @details 通过 DNS 解析获取目标地址，然后创建 UDP 套接字。
     * @param rt 路由器引用
     * @param host 目标主机名
     * @param port 目标服务端口
     * @return 协程对象，返回结果码与 UDP 套接字的配对
     */
    [[nodiscard]] auto async_datagram(router &rt, std::string_view host, std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>;

    /**
     * @brief 解析数据报目标端点
     * @details 仅返回解析后的端点信息，不创建套接字。
     * @param rt 路由器引用
     * @param host 目标主机名
     * @param port 目标服务端口
     * @return 协程对象，返回结果码与 UDP 端点的配对
     */
    [[nodiscard]] auto resolve_dgram(router &rt, std::string_view host, std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>;

    /**
     * @brief 打开 UDP 套接字
     * @details 根据目标端点的地址类型自动选择 IPv4 或 IPv6 协议。
     * @param executor 用于创建套接字的执行器
     * @param target 目标 UDP 端点，用于确定协议版本
     * @return 包含结果码和 UDP 套接字的配对
     */
    [[nodiscard]] inline auto open_udp(const net::any_io_executor &executor, const net::ip::udp::endpoint &target)
        -> std::pair<fault::code, net::ip::udp::socket>
    {
        boost::system::error_code ec;
        net::ip::udp::socket socket(executor);

        auto protocol = net::ip::udp::v4();
        if (target.address().is_v6())
        {
            protocol = net::ip::udp::v6();
        }
        socket.open(protocol, ec);
        if (ec)
        {
            return std::pair{fault::code::io_error, net::ip::udp::socket(executor)};
        }

        return std::pair{fault::code::success, std::move(socket)};
    }

    /**
     * @brief 创建 UDP 数据报路由回调
     * @param rt 路由器引用
     * @return UDP 路由回调函数
     * @details 创建用于 UDP ASSOCIATE 的路由回调函数，避免每个协议重复构造。
     * @warning 返回的回调持有 rt 的非拥有引用（空删除器 shared_ptr），
     * 调用方必须确保 rt 的生命周期长于回调的使用期。
     */
    [[nodiscard]] inline auto make_router(router &rt)
        -> std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view, std::string_view)>
    {
        const auto ptr = std::shared_ptr<router>(&rt, [](router *) {});
        return [ptr](const std::string_view host, const std::string_view port)
                   -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
        {
            co_return co_await resolve_dgram(*ptr, host, port);
        };
    }

    /**
     * @struct dial_options
     * @brief 拨号路由策略选项
     * @details 封装拨号时的路由策略标志和目标信息，将 dial 函数参数收敛到 2 个。
     */
    struct dial_options
    {
        std::string_view label;              ///< 协议标签，用于日志记录
        const protocol::target &target;      ///< 解析后的上游目标地址

        /**
         * @brief 路由策略标志
         * @details 控制拨号时是否允许反向路由、是否要求已打开的套接字
         */
        enum class flag : std::uint8_t
        {
            normal,              ///< 正常模式：允许反向路由，要求套接字已打开
            no_reverse,          ///< 禁止反向路由
            no_open,              ///< 不要求套接字已打开
            neither               ///< 禁止反向路由 + 不要求套接字已打开
        };

        flag routing{flag::normal};          ///< 路由策略标志
    };

    /**
     * @brief 拨号连接上游服务器并包装为可靠传输
     * @param rt 路由器引用
     * @param opts 路由策略选项（标签、目标地址、反向路由标志等）
     * @return 协程对象，完成后返回结果码和传输对象的配对
     */
    [[nodiscard]] auto dial(router &rt, dial_options opts)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>;

    /**
     * @brief 通过出站代理拨号连接上游
     * @param outbound_proxy 出站代理引用
     * @param target 目标地址信息
     * @param executor 用于创建连接的执行器
     * @return 协程对象，完成后返回结果码和传输对象的配对
     */
    [[nodiscard]] auto dial(outbound::proxy &outbound_proxy, const protocol::target &target, const net::any_io_executor &executor)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>;

} // namespace psm::connect
