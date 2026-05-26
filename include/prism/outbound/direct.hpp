/**
 * @file direct.hpp
 * @brief 直连出站代理实现
 * @details 包装现有 connect::router + connect::connection_pool 的直连行为，
 * 作为最简单的 outbound::proxy 实现。所有连接请求直接通过 DNS 解析
 * 和 Happy Eyeballs 建立连接，不经过任何上游代理。
 * 等价于 mihomo 的 adapter/outbound/direct.go。
 * @note 该类为 header-only 实现，每个 worker 持有一个实例。
 * @warning 生命周期由 worker 管理，router 引用必须比 direct 实例长寿。
 */
#pragma once

#include <prism/connect/dial/dial.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/connect/pool/pool.hpp>
#include <prism/fault/code.hpp>
#include <prism/outbound/proxy.hpp>
#include <prism/trace.hpp>
#include <prism/transport/reliable.hpp>

#include <string_view>
#include <utility>


namespace psm::outbound
{

    /**
     * @class direct
     * @brief 直连出站代理
     * @details 将 outbound::proxy 接口映射到现有的 connect::router 路由。
     * 路由策略：
     * - target.positive == false 时尝试反向路由（域名 → 预配置后端）
     * - 否则走正向路由（DNS 解析 + TCP 连接）
     *
     * 该实现完整复刻了原 primitives::dial() 的行为逻辑，
     * 包括 IPv6 禁用检查和连接有效性验证。
     */
    class direct : public proxy
    {
    public:
        /**
         * @brief 构造直连出站代理
         * @param router 路由器引用，用于 DNS 解析和连接建立
         */
        explicit direct(connect::router &router)
            : router_(router)
        {
        }

        [[nodiscard]] auto async_connect(const protocol::target &target, const net::any_io_executor &executor)
            -> net::awaitable<std::pair<fault::code, shared_transmission>> override
        {
            // 拒绝 IPv6 地址字面量（仅在禁用 IPv6 时）
            if (router_.ipv6_disabled() && is_ipv6(target.host))
            {
                trace::debug("[Outbound.Direct] rejecting IPv6 literal: {}:{}", target.host, target.port);
                co_return std::pair{fault::code::ipv6_disabled, nullptr};
            }

            // 路由到目标
            fault::code ec;
            psm::connect::pooled_connection conn;

            if (!target.positive)
            {
                // 反向代理：域名 → 预配置的后端地址
                auto result = co_await router_.async_reverse(target.host);
                ec = result.first;
                conn = std::move(result.second);
            }
            else
            {
                // 正向代理：域名 → DNS 解析 → TCP 连接
                auto result = co_await connect::async_forward(router_, target.host, target.port);
                ec = result.first;
                conn = std::move(result.second);
            }

            if (fault::failed(ec))
            {
                trace::warn("[Outbound.Direct] route failed: {}, target: {}:{}", fault::describe(ec),
                            target.host, target.port);
                co_return std::pair{ec, nullptr};
            }

            if (!conn.valid())
            {
                trace::warn("[Outbound.Direct] socket not open, target: {}:{}", target.host, target.port);
                co_return std::pair{fault::code::connection_refused, nullptr};
            }

            trace::info("[Outbound.Direct] success, target: {}:{}", target.host, target.port);
            co_return std::pair{fault::code::success,
                                transport::make_reliable(std::move(conn))};
        }

        [[nodiscard]] auto make_router()
            -> std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(
                std::string_view, std::string_view)> override
        {
            const auto ptr = std::shared_ptr<connect::router>(&router_, []([[maybe_unused]] connect::router *p)
                                                              {
                                                                  // 非拥有指针，空删除器
                                                              });
            return [ptr](const std::string_view host, const std::string_view port)
                       -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
            {
                co_return co_await connect::resolve_dgram(*ptr, host, port);
            };
        }

        [[nodiscard]] auto name() const
            -> std::string_view override
        {
            return "DIRECT";
        }

    private:
        /**
         * @brief 检查目标地址是否为 IPv6 字面量
         * @param host 目标主机名或 IP 地址
         * @return 如果是 IPv6 地址字面量返回 true
         */
        [[nodiscard]] static auto is_ipv6(const std::string_view host) noexcept
            -> bool
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            return !ec && addr.is_v6();
        }

        connect::router &router_;
    };

} // namespace psm::outbound
