/**
 * @file Outbound.hpp
 * @brief 出站拨号上下文（路由 + Dialer 组合）
 * @details 统一出站入口：
 *          - Dial(Target)：按路由表解析目标 → Dialer 拨号
 *          - 供 Middleware/builtin/Dial 中间件注入（T4）
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <common/Core/Error.hpp>
#include <common/Core/Net/Dialer/Dialer.hpp>
#include <common/Core/Net/Route/Route.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview::Network::Outbound
{

    namespace net = boost::asio;

    /**
     * @struct Target
     * @brief 拨号目标
     */
    struct Target
    {
        std::string_view Host;      ///< 目标主机
        std::uint16_t Port{0};      ///< 目标端口
        bool positive{false};       ///< 是否强制正向（不查反向路由）
    };

    /**
     * @class Outbound
     * @brief 出站拨号器（路由感知）
     */
    class Outbound
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param routes 路由表（共享所有权）
         */
        explicit Outbound(net::any_io_executor ex, std::shared_ptr<Preview::Network::Route::RouteTable> routes)
            : Ex_(std::move(ex)), Routes_(std::move(routes))
        {
        }

        /**
         * @brief 拨号（按路由解析目标）
         * @param tgt 拨号目标
         * @param ec 错误码输出
         * @return 连接成功的传输；失败返回 nullptr
         * @details 反向映射命中 → 用映射端点；否则用原目标。
         */
        [[nodiscard]] auto Dial(const Target &tgt, std::error_code &ec) -> net::awaitable<SharedTransmission>
        {
            std::string_view DialHost = tgt.Host;
            std::uint16_t DialPort = tgt.Port;
            if (!tgt.positive && Routes_)
            {
                if (const auto Route = Routes_->Lookup(tgt.Host); Route.has_value())
                {
                    DialHost = Route->Host;
                    DialPort = Route->Port;
                }
            }
            if (DialPort == 0)
            {
                ec = make_error_code(Error::BadAddress);
                co_return nullptr;
            }
            Preview::Network::Dialer::Dialer Dialer(Ex_);
            co_return co_await Dialer.Connect(DialHost, DialPort, ec);
        }

    private:
        net::any_io_executor Ex_;
        std::shared_ptr<Preview::Network::Route::RouteTable> Routes_;
    };

} // namespace Preview::Network::Outbound
