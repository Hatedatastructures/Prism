/**
 * @file proxy.hpp
 * @brief 出站代理抽象接口
 * @details 定义所有出站协议（direct, socks5, http, trojan, vless, ss 等）
 * 以及代理组（url_test, fallback, load_balance, selector）必须实现的核心接口。
 * 该接口采用纯协程设计，使用 net::awaitable 作为异步操作返回类型，
 * 通过组合模式使代理组和单个代理共享同一接口，调用方无需区分。
 * 等价于 mihomo 的 C.ProxyAdapter 接口。
 * @note 所有异步操作通过 std::error_code& 参数返回错误，避免异常开销。
 * @warning 接口方法都是纯虚函数，必须由子类实现。
 */
#pragma once

#include <functional>
#include <memory>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>
#include <prism/fault/code.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/protocol/analysis.hpp>

namespace psm::outbound
{
    namespace net = boost::asio;
    using shared_transmission = channel::transport::shared_transmission;

    /// UDP 数据报路由回调类型
    using datagram_router_fn = std::function<net::awaitable<std::pair<fault::code,
                                                                      net::ip::udp::endpoint>>(std::string_view, std::string_view)>;

    /**
     * @class proxy
     * @brief 出站代理抽象接口
     * @details 所有出站协议和代理组必须实现此接口。核心方法包括
     * TCP 连接建立和 UDP 路由回调。代理组通过组合模式委托给子代理，
     * 调用方透明地与单个代理或代理组交互。
     *
     * 设计特性:
     * - 纯协程: 异步操作返回 net::awaitable
     * - 错误码: 通过 fault::code 返回错误，无异常开销
     * - 组合模式: 代理组实现同一接口，透明委托
     *
     * 等价于 mihomo 的 constant/adapters.go 中 ProxyAdapter 接口。
     * @note 代理组（url_test, fallback 等）也实现此接口，通过组合模式
     * 委托给子代理的 async_connect。
     */
    class proxy
    {
    public:
        virtual ~proxy() = default;

        /**
         * @brief 建立 TCP 连接到目标
         * @param target 目标地址信息（host + port + positive 标记）
         * @param executor 用于创建连接的执行器
         * @return 协程对象，完成后返回 (错误码, 传输对象) 对
         * @details 实现类内部决定路由策略：直连走 DNS 解析 + 连接池，
         * 代理走上游协议握手，代理组走子代理选择。
         */
        virtual auto async_connect(const protocol::analysis::target &target, const net::any_io_executor &executor)
            -> net::awaitable<std::pair<fault::code, shared_transmission>> = 0;

        /**
         * @brief 创建 UDP 数据报路由回调
         * @return 回调函数，接受 (host, port) 返回 (错误码, udp_endpoint)
         * @details 替代直接传递 router 引用，将 DNS 解析封装在实现内部。
         */
        virtual auto make_datagram_router()
            -> datagram_router_fn = 0;

        /**
         * @brief 获取代理名称
         * @return 代理名称的字符串视图
         */
        [[nodiscard]] virtual auto name() const -> std::string_view = 0;

        /**
         * @brief 是否支持 UDP
         * @return 默认返回 true，不支持 UDP 的代理应重写
         */
        [[nodiscard]] virtual auto supports_udp() const -> bool { return true; }
    };

} // namespace psm::outbound
