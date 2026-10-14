/**
 * @file EndpointResolver.hpp
 * @brief DNS 上游端点解析与缓存 owner
 * @details 只负责将上游 host/port 解析为 TCP 端点并缓存结果。UDP、TCP、
 *          DoT 和 DoH 的查询编排由 QueryExecutor 负责。
 */

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace Preview::Network::Dns::Detail
{

    namespace Net = boost::asio;

    /**
     * @class EndpointResolver
     * @brief 单 io_context 内共享的 DNS 上游端点解析器
     * @note 端点缓存与解析器执行器属于该对象；调用者只拥有查询生命周期。
     */
    class EndpointResolver
    {
    public:
        explicit EndpointResolver(Net::any_io_executor Executor) : Ex_(std::move(Executor))
        {
        }

        /**
         * @brief 解析上游地址为端点
         * @param Host 上游主机名或 IP
         * @param Port 上游端口
         * @param Error [out] 解析错误
         * @return 首个解析端点；失败时返回空端点
         */
        [[nodiscard]] auto Resolve(const std::string_view Host, const std::uint16_t Port,
                                   boost::system::error_code &Error)
            -> Net::awaitable<Net::ip::tcp::endpoint>
        {
            const auto CacheKey = std::string(Host) + ':' + std::to_string(Port);
            if (const auto It = EndpointCache_.find(CacheKey); It != EndpointCache_.end())
            {
                co_return It->second;
            }

            Net::ip::tcp::resolver ResolverObject(Ex_);
            auto Results = co_await ResolverObject.async_resolve(
                std::string(Host), std::to_string(Port), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Results.begin() == Results.end())
            {
                co_return Net::ip::tcp::endpoint{};
            }

            const auto EndpointValue = Results.begin()->endpoint();
            EndpointCache_.emplace(CacheKey, EndpointValue);
            co_return EndpointValue;
        }

    private:
        Net::any_io_executor Ex_;
        std::unordered_map<std::string, Net::ip::tcp::endpoint> EndpointCache_;
    };

} // namespace Preview::Network::Dns::Detail
