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

#include <Preview/Foundation/Error.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Net/Route/Route.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Network::Outbound
{

    namespace Net = boost::asio;

    /**
     * @struct Target
     * @brief 拨号目标
     */
    struct Target
    {
        std::string_view Host;      ///< 目标主机
        std::uint16_t Port{0};      ///< 目标端口
        bool Positive{false};       ///< 是否强制正向（不查反向路由）
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
        explicit Outbound(Net::any_io_executor Executor,
                          std::shared_ptr<Preview::Network::Route::RouteTable> Routes)
            : Ex_(std::move(Executor)), Routes_(std::move(Routes))
        {
        }

        /**
         * @brief 拨号（按路由解析目标）
         * @param tgt 拨号目标
         * @param ec 错误码输出
         * @return 连接成功的传输；失败返回 nullptr
         * @details 反向映射命中 → 用映射端点；否则用原目标。
         */
        [[nodiscard]] auto Dial(const Target &TargetValue, std::error_code &ErrorCode)
            -> Net::awaitable<SharedTransmission>
        {
            std::string_view DialHost = TargetValue.Host;
            std::uint16_t DialPort = TargetValue.Port;
            if (!TargetValue.Positive && Routes_)
            {
                if (const auto Route = Routes_->Lookup(TargetValue.Host); Route.has_value())
                {
                    DialHost = Route->Host;
                    DialPort = Route->Port;
                }
            }
            if (DialPort == 0)
            {
                ErrorCode = make_error_code(Error::BadAddress);
                co_return nullptr;
            }
            Preview::Network::Dialer::Dialer Dialer(Ex_);
            co_return co_await Dialer.Connect(DialHost, DialPort, ErrorCode);
        }

    private:
        Net::any_io_executor Ex_;
        std::shared_ptr<Preview::Network::Route::RouteTable> Routes_;
    };

} // namespace Preview::Network::Outbound
