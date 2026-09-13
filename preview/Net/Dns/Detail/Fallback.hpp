/**
 * @file Fallback.hpp
 * @brief DNS 上游结果与 Fallback 查询策略细节
 * @details 提供结果校验、失败包装、Fastest 选择和 Fallback 顺序策略。
 *          查询/超时行为通过模板回调注入，保持调用边界静态分发，避免
 *          在 DNS 查询路径引入 std::function 或额外类型擦除。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Net/Dns/Answer.hpp>
#include <preview/Net/Dns/Types.hpp>

namespace Preview::Network::Dns::Detail
{

    /**
     * @brief 构造已校验的 DNS 查询结果
     * @param scan 应答扫描结果
     * @param addr 上游地址
     * @param start 查询开始时间
     * @return 规范化查询结果
     */
    [[nodiscard]] inline auto BuildCheckedResult(const AnswerSet &Scan, const std::string &Address,
                                                  std::chrono::steady_clock::time_point Start)
        -> QueryResult
    {
        QueryResult Result;
        Result.Response = Scan;
        Result.ServerAddr = Address;
        Result.RttMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - Start)
                .count());
        if (Scan.Rcode != 0 && Scan.Rcode != 3)
        {
            Result.Error = make_error_code(Error::ProtocolError);
            return Result;
        }
        Result.Ips.assign(Scan.Ips.begin(), Scan.Ips.end());
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
        Result.Error = ErrorCode;
        return Result;
    }

    /**
     * @brief 顺序尝试全部上游
     * @tparam QueryFn 单服务器查询回调
     * @tparam TimeoutFn 查询超时包装回调
     * @param Servers 上游服务器列表
     * @param query 查询消息
     * @param qtNum 查询类型数值
     * @param queryFn 单服务器查询回调
     * @param timeoutFn 超时包装回调
     * @return 首个成功结果；全部失败返回最后一个结果
     */
    template <typename QueryMessage, typename QueryFn, typename TimeoutFn>
    [[nodiscard]] inline auto ResolveFallback(const std::vector<Server> &Servers,
                                              const QueryMessage &query, const std::uint16_t qtNum,
                                              QueryFn queryFn, TimeoutFn timeoutFn)
        -> boost::asio::awaitable<QueryResult>
    {
        QueryResult Last;
        for (const auto &ServerConfig : Servers)
        {
            Last = co_await timeoutFn(queryFn(ServerConfig, query, qtNum), ServerConfig);
            if (!Last.Error && (!Last.Ips.empty() || Last.Response.Rcode == 3))
            {
                co_return Last;
            }
        }
        if (!Last.Error)
        {
            Last.Error = make_error_code(Error::BadAddress);
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
            if (!Result.Error && !Result.Ips.empty() && (!Best || Result.RttMs < Best->RttMs))
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
        FailedResult.Error = make_error_code(Error::BadAddress);
        return FailedResult;
    }

} // namespace Preview::Network::Dns::Detail
