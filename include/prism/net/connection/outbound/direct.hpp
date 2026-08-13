/**
 * @file direct.hpp
 * @brief 直连出站（具体类）
 * @details 包装 connect::dialer 的直连行为。路由策略（IPv6 检查、
 *          正反向路由）由 dialer::connect 统一处理。单一实现不抽象：
 *          不继承任何虚接口，调用方直接持有 direct 引用。
 * @note 该类为 header-only 实现，每个 worker 持有一个实例。
 * @warning 生命周期由 worker 管理，dialer 引用必须比 direct 实例长寿。
 */
#pragma once

#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/transmission.hpp>

#include <functional>
#include <string_view>
#include <utility>

namespace psm::outbound
{
    using namespace psm::diagnose; // NOLINT(google-build-using-namespace)

    namespace net = boost::asio;
    using shared_transmission = transport::shared_transmission;

    /// UDP 数据报路由回调类型
    using router_fn = std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(
        std::string_view, std::string_view)>;

    /**
     * @class direct
     * @brief 直连出站（具体类）
     * @details 将 dialer 拨号能力暴露给上层：async_connect 建立 TCP 连接，
     *          make_router 提供 UDP 端点解析回调。
     */
    class direct
    {
    public:
        /**
         * @brief 构造直连出站
         * @param dialer 拨号器引用，用于 DNS 解析和连接建立
         */
        explicit direct(connect::dialer &dialer) : dialer_(dialer)
        {
        }

        /**
         * @brief 建立到目标的连接
         * @param target 拨号目标（主机 + 端口 + 路由策略）
         * @param executor 执行器（由 dialer 内部使用，保持签名兼容）
         * @return 结果码 + 可靠传输（失败时空）
         */
        [[nodiscard]] auto async_connect(const psm::connect::target &target,
                                         const net::any_io_executor &executor)
            -> net::awaitable<std::pair<fault::code, shared_transmission>>
        {
            auto [ec, conn] = co_await dialer_.connect(target);
            if (fault::failed(ec) || !conn)
            {
                diagnose::warn("route failed: {}, target: {}:{}", fault::describe(ec), target.host,
                               target.port);
                co_return std::pair{ec, nullptr};
            }

            diagnose::info("success, target: {}:{}", target.host, target.port);
            co_return std::pair{fault::code::success, std::move(conn)};
        }

        /**
         * @brief 提供 UDP 端点解析回调
         * @return 解析回调（host, port → 结果码 + UDP 端点）
         */
        [[nodiscard]] auto make_router() -> router_fn
        {
            const auto ptr = std::shared_ptr<connect::dialer>(&dialer_,
                                                              []([[maybe_unused]] connect::dialer *p)
                                                              {
                                                                  // 非拥有指针，空删除器
                                                              });
            return [ptr](const std::string_view host, const std::string_view port)
                       -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
            { co_return co_await ptr->resolve_dgram(host, port); };
        }

    private:
        connect::dialer &dialer_;
    };

} // namespace psm::outbound
