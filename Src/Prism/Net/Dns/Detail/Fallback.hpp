/**
 * @file Fallback.hpp
 * @brief DNS 上游结果与 Fallback 查询策略细节
 * @details 提供结果校验、失败包装、Fastest 选择和 Fallback 顺序策略。
 *          查询行为通过模板回调注入，保持调用边界静态分发，避免在 DNS
 *          查询路径引入 std::function 或额外类型擦除；单次尝试的绝对
 *          deadline 由 QueryExecutor 内部竞速，Fallback 不再叠加超时层。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Net/Dns/Detail/ResolverFailure.hpp>
#include <Prism/Net/Dns/Answer.hpp>
#include <Prism/Net/Dns/UpstreamTypes.hpp>

namespace Prism::Network::Dns::Detail
{

    /**
     * @brief 构造已校验的 DNS 查询结果
     * @param Scan 按值接管的校验应答；地址与摘要共用同一实际结果
     * @param addr 上游地址
     * @param start 查询开始时间
     * @return 规范化查询结果
     */
    [[nodiscard]] inline auto BuildCheckedResult(AnswerSet Scan, const std::string &Address,
                                                  std::chrono::steady_clock::time_point Start)
        -> QueryResult
    {
        QueryResult Result;
        Result.ServerAddr = Address;
        Result.RttMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - Start)
                .count());
        if (Scan.Rcode != 0 && Scan.Rcode != 3)
        {
            Result.Error = Prism::Fault::Failure{Prism::Fault::Code::ProtocolError, {}};
            return Result;
        }
        Result.Response = std::move(Scan);
        return Result;
    }

    /**
     * @brief 构造失败结果
     * @param addr 上游地址
     * @param ec 失败错误码
     * @return 带来源地址的失败结果
     */
    [[nodiscard]] inline auto FailResult(const std::string &Address,
                                         boost::system::error_code ErrorCode)
        -> QueryResult
    {
        QueryResult Result;
        Result.ServerAddr = Address;
        Result.Error = ResolverFailureFromBoost(ErrorCode);
        return Result;
    }

    /**
     * @brief 一次顺序 Fallback 查询的值请求。
     * @details Servers、Query 和回调随异步请求按值存活；不借用临时 wire buffer。
     */
    template <typename QueryMessage, typename QueryFn>
    struct FallbackRequest final
    {
        std::vector<Server> Servers;
        QueryMessage Query;
        QueryFn QueryFunction;
    };

    /**
     * @brief 顺序尝试全部上游。
     * @tparam QueryMessage 查询消息值类型。
     * @tparam QueryFn 单服务器查询回调。
     * @param Request 按值拥有的上游快照、查询消息与查询回调。
     * @return 首个成功结果；全部失败返回最后一个结果。
     * @details 不引入 std::function、动态注册或第二套 DNS 结果事实。
     */
    template <typename QueryMessage, typename QueryFn>
    [[nodiscard]] inline auto ResolveFallback(FallbackRequest<QueryMessage, QueryFn> Request)
        -> boost::asio::awaitable<QueryResult>
    {
        QueryResult Last;
        for (const auto &ServerConfig : Request.Servers)
        {
            Last = co_await Request.QueryFunction(ServerConfig, Request.Query);
        if (Last.Error.Succeeded() && (!Last.Response.Ips.Empty() || Last.Response.Rcode == 3))
            {
                co_return Last;
            }
        }
        if (Last.Error.Succeeded())
        {
            Last.Error = Prism::Fault::Failure{Prism::Fault::Code::DnsFailed, {}};
        }
        co_return Last;
    }

    /**
     * @brief 从全部结果中选择最低 RTT 的成功项
     * @param Results 查询结果
     * @return 最优成功结果；全败返回首个结果
     */
    [[nodiscard]] inline auto SelectBest(std::vector<QueryResult> &Results) -> QueryResult
    {
        QueryResult *Best = nullptr;
        for (auto &Result : Results)
        {
            if (Result.Error.Succeeded() && !Result.Response.Ips.Empty() &&
                (!Best || Result.RttMs < Best->RttMs))
            {
                Best = &Result;
            }
        }
        if (Best)
        {
            return std::move(*Best);
        }
        if (!Results.empty())
        {
            return std::move(Results.front());
        }
        QueryResult FailedResult;
        FailedResult.Error = Prism::Fault::Failure{Prism::Fault::Code::DnsFailed, {}};
        return FailedResult;
    }

} // namespace Prism::Network::Dns::Detail
