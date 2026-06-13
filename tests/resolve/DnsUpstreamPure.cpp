/**
 * @file DnsUpstreamPure.cpp
 * @brief DNS upstream 纯函数单元测试
 * @details 测试 upstream::select_best_result 的核心逻辑。
 *          由于 select_best_result 是 private 方法，此处提取其纯算法逻辑
 *          进行独立验证，覆盖最快响应选择、全失败回退、空结果集和混合成功/失败场景。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/core/fault/handling.hpp>
#include <prism/net/resolve/dns/upstream.hpp>


#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <cstdint>

namespace
{
    namespace net = boost::asio;

    using psm::resolve::dns::query_result;

    /**
     * @brief 辅助函数：构造一个指定参数的查询结果
     */
    auto make_result(psm::fault::code error,
                     std::uint64_t rtt_ms,
                     const char *server_addr = "")
        -> query_result
    {
        query_result result;
        result.error = error;
        result.rtt_ms = rtt_ms;
        result.server_addr = psm::memory::string(server_addr);

        if (psm::fault::succeeded(error))
        {
            result.ips.push_back(net::ip::make_address("1.2.3.4"));
        }

        return result;
    }

    /**
     * @brief 提取自 upstream::select_best_result 的纯算法逻辑
     *        选择 RTT 最低的成功响应，全失败返回第一个，空返回 dns_failed
     */
    auto select_best(psm::memory::vector<query_result> &results)
        -> query_result
    {
        query_result *best = nullptr;
        for (auto &r : results)
        {
            if (psm::fault::succeeded(r.error) && !r.ips.empty())
            {
                if (!best || r.rtt_ms < best->rtt_ms)
                {
                    best = &r;
                }
            }
        }
        if (best)
        {
            return std::move(*best);
        }

        if (!results.empty())
        {
            return std::move(results.front());
        }

        query_result fallback;
        fallback.error = psm::fault::code::dns_failed;
        return fallback;
    }

    // ─── 最快模式：返回 RTT 最低的成功结果 ───────────

    TEST(DnsUpstreamPure, SelectBestFastestMode)
    {
        psm::memory::vector<query_result> results;
        results.push_back(make_result(psm::fault::code::success, 100, "server-a"));
        results.push_back(make_result(psm::fault::code::success, 50, "server-b"));
        results.push_back(make_result(psm::fault::code::success, 200, "server-c"));

        auto best = select_best(results);

        EXPECT_TRUE(psm::fault::succeeded(best.error))
            << "select_best fastest: 成功返回";
        EXPECT_TRUE(best.rtt_ms == 50)
            << "select_best fastest: RTT=50（最低）";
        EXPECT_TRUE(best.server_addr == "server-b")
            << "select_best fastest: server-b";
    }

    // ─── 全失败：返回第一个结果 ──────────────────────

    TEST(DnsUpstreamPure, SelectBestAllFailed)
    {
        psm::memory::vector<query_result> results;
        results.push_back(make_result(psm::fault::code::timeout, 300, "server-a"));
        results.push_back(make_result(psm::fault::code::io_error, 500, "server-b"));
        results.push_back(make_result(psm::fault::code::timeout, 200, "server-c"));

        auto best = select_best(results);

        EXPECT_TRUE(best.server_addr == "server-a")
            << "select_best all failed: 返回第一个";
        EXPECT_TRUE(best.error == psm::fault::code::timeout)
            << "select_best all failed: 保留原始错误码";
    }

    // ─── 空结果集 ─────────────────────────────────────

    TEST(DnsUpstreamPure, SelectBestEmpty)
    {
        psm::memory::vector<query_result> results;

        auto best = select_best(results);

        EXPECT_TRUE(best.error == psm::fault::code::dns_failed)
            << "select_best empty: 返回 dns_failed";
        EXPECT_TRUE(best.ips.empty())
            << "select_best empty: 无 IP 结果";
    }

    // ─── 混合场景：部分成功部分失败 ───────────────────

    TEST(DnsUpstreamPure, SelectBestMixed)
    {
        psm::memory::vector<query_result> results;
        results.push_back(make_result(psm::fault::code::timeout, 300, "server-a"));
        results.push_back(make_result(psm::fault::code::success, 150, "server-b"));
        results.push_back(make_result(psm::fault::code::io_error, 50, "server-c"));
        results.push_back(make_result(psm::fault::code::success, 80, "server-d"));

        auto best = select_best(results);

        EXPECT_TRUE(psm::fault::succeeded(best.error))
            << "select_best mixed: 成功返回";
        EXPECT_TRUE(best.rtt_ms == 80)
            << "select_best mixed: RTT=80（最快成功）";
        EXPECT_TRUE(best.server_addr == "server-d")
            << "select_best mixed: server-d（最快成功）";
    }

    // ─── 仅有单个成功结果 ────────────────────────────

    TEST(DnsUpstreamPure, SelectBestSingleSuccess)
    {
        psm::memory::vector<query_result> results;
        results.push_back(make_result(psm::fault::code::success, 999, "only-one"));

        auto best = select_best(results);

        EXPECT_TRUE(psm::fault::succeeded(best.error))
            << "select_best single: 成功返回";
        EXPECT_TRUE(best.rtt_ms == 999)
            << "select_best single: RTT=999";
        EXPECT_TRUE(best.server_addr == "only-one")
            << "select_best single: only-one";
    }

    // ─── 成功但 ips 为空：视为失败 ────────────────────

    TEST(DnsUpstreamPure, SelectBestSuccessEmptyIps)
    {
        psm::memory::vector<query_result> results;
        query_result empty_ip_result;
        empty_ip_result.error = psm::fault::code::success;
        empty_ip_result.rtt_ms = 10;
        empty_ip_result.server_addr = psm::memory::string("empty-ips");
        // ips is empty -> should be skipped
        results.push_back(std::move(empty_ip_result));

        auto best = select_best(results);

        EXPECT_TRUE(best.server_addr == "empty-ips")
            << "select_best empty ips: 回退到第一个";
    }

    // ─── 同 RTT 多成功：取第一个 ──────────────────────

    TEST(DnsUpstreamPure, SelectBestSameRtt)
    {
        psm::memory::vector<query_result> results;
        results.push_back(make_result(psm::fault::code::success, 100, "first"));
        results.push_back(make_result(psm::fault::code::success, 100, "second"));

        auto best = select_best(results);

        EXPECT_TRUE(best.server_addr == "first")
            << "select_best same RTT: 取第一个";
    }

} // namespace
