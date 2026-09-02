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
    [[nodiscard]] inline auto BuildCheckedResult(const AnswerSet &scan, const std::string &addr,
                                                  std::chrono::steady_clock::time_point start)
        -> QueryResult
    {
        QueryResult out;
        out.Response = scan;
        out.ServerAddr = addr;
        out.RttMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start)
                .count());
        if (scan.Rcode != 0 && scan.Rcode != 3)
        {
            out.Error = make_error_code(Error::ProtocolError);
            return out;
        }
        out.Ips.assign(scan.Ips.begin(), scan.Ips.end());
        return out;
    }

    /**
     * @brief 构造失败结果
     * @param addr 上游地址
     * @param ec 失败错误码
     * @return 带来源地址的失败结果
     */
    [[nodiscard]] inline auto FailResult(const std::string &addr, boost::system::error_code ec)
        -> QueryResult
    {
        QueryResult out;
        out.ServerAddr = addr;
        out.Error = ec;
        return out;
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
        QueryResult last;
        for (const auto &server : Servers)
        {
            last = co_await timeoutFn(queryFn(server, query, qtNum), server);
            if (!last.Error && (!last.Ips.empty() || last.Response.Rcode == 3))
            {
                co_return last;
            }
        }
        if (!last.Error)
        {
            last.Error = make_error_code(Error::BadAddress);
        }
        co_return last;
    }

    /**
     * @brief 从全部结果中选择最低 RTT 的成功项
     * @param Results 查询结果
     * @return 最优成功结果；全败返回首个结果
     */
    [[nodiscard]] inline auto SelectBest(std::vector<QueryResult> &Results) -> QueryResult
    {
        QueryResult *best = nullptr;
        for (auto &result : Results)
        {
            if (!result.Error && !result.Ips.empty() && (!best || result.RttMs < best->RttMs))
            {
                best = &result;
            }
        }
        if (best)
        {
            return std::move(*best);
        }
        if (!Results.empty())
        {
            return std::move(Results.front());
        }
        QueryResult failed;
        failed.Error = make_error_code(Error::BadAddress);
        return failed;
    }

} // namespace Preview::Network::Dns::Detail
