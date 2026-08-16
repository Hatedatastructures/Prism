/**
 * @file outbound.hpp
 * @brief 出站拨号上下文（路由 + dialer 组合）
 * @details 统一出站入口：
 *          - dial(target)：按路由表解析目标 → dialer 拨号
 *          - 供 middleware/builtin/dial 中间件注入（T4）
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <common/core/error.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/net/route/route.hpp>
#include <common/core/transmission.hpp>

namespace psmtest::outbound
{

    namespace net = boost::asio;

    /**
     * @struct target
     * @brief 拨号目标
     */
    struct target
    {
        std::string_view host;      ///< 目标主机
        std::uint16_t port{0};      ///< 目标端口
        bool positive{false};       ///< 是否强制正向（不查反向路由）
    };

    /**
     * @class outbound
     * @brief 出站拨号器（路由感知）
     */
    class outbound
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param routes 路由表（共享所有权）
         */
        explicit outbound(net::any_io_executor ex, std::shared_ptr<net_route::route_table> routes)
            : ex_(std::move(ex)), routes_(std::move(routes))
        {
        }

        /**
         * @brief 拨号（按路由解析目标）
         * @param tgt 拨号目标
         * @param ec 错误码输出
         * @return 连接成功的传输；失败返回 nullptr
         * @details 反向映射命中 → 用映射端点；否则用原目标。
         */
        [[nodiscard]] auto dial(const target &tgt, std::error_code &ec) -> net::awaitable<shared_transmission>
        {
            std::string_view dial_host = tgt.host;
            std::uint16_t dial_port = tgt.port;
            if (!tgt.positive && routes_)
            {
                if (const auto route = routes_->lookup(tgt.host); route.has_value())
                {
                    dial_host = route->host;
                    dial_port = route->port;
                }
            }
            if (dial_port == 0)
            {
                ec = make_error_code(error::bad_address);
                co_return nullptr;
            }
            net_dialer::dialer dialer(ex_);
            co_return co_await dialer.connect(dial_host, dial_port, ec);
        }

    private:
        net::any_io_executor ex_;
        std::shared_ptr<net_route::route_table> routes_;
    };

} // namespace psmtest::outbound
