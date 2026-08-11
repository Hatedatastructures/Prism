/**
 * @file UdpRelayStress.cpp
 * @brief UDP 数据报中继压力测试
 * @details 控制变量法：变量 = 报文大小 × 并发转发链。
 * 使用真实 UDP socket 对（loopback），模拟客户端→中继→上游的
 * 数据报转发路径，测量吞吐（MB/s）与包速率（pps），
 * 覆盖小报文（信令类）到大报文（媒体流类）的负载特征。
 */

#include <prism/foundation/memory/pool.hpp>

#include "StressUtil.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

using namespace psm;
namespace memory = psm::memory;
using namespace psm::stress;

namespace
{
    namespace net = boost::asio;

    /**
     * @brief UDP 场景定义
     */
    struct udp_scenario
    {
        std::string name;                ///< 场景名称
        std::size_t dgram{512};          ///< 报文大小
        std::size_t chains{1};           ///< 并发转发链数
        std::size_t duration_ms{3000};   ///< 持续时间
    };

    /**
     * @brief 结果
     */
    struct udp_result
    {
        std::uint64_t dgrams{0};      ///< 接收报文数
        std::uint64_t sent{0};        ///< 发送报文数
        std::uint64_t errors{0};      ///< 序号错误（丢包/乱序）
        double seconds{0};
        double mbps{0};
        double pps{0};
        double loss_pct{0};           ///< 丢包率
        bool pass{false};
    };

    /**
     * @brief 转发链：sender → 中继转发 → receiver 校验
     */
    auto relay_chain(net::any_io_executor ex, const udp_scenario &sc,
                     const std::atomic<bool> &stop, std::atomic<std::uint64_t> &received,
                     std::atomic<std::uint64_t> &sent, std::atomic<std::uint64_t> &errors,
                     const std::size_t seed) -> net::awaitable<void>
    {
        // 三段：客户端 UDP / 中继 UDP（转发）/ 上游 UDP（接收校验）
        net::ip::udp::socket client(ex);
        net::ip::udp::socket relay(ex);
        net::ip::udp::socket upstream(ex);
        client.open(net::ip::udp::v4());
        relay.open(net::ip::udp::v4());
        upstream.open(net::ip::udp::v4());
        // Windows UDP 默认接收缓冲仅 8KB，高速转发下丢包严重；
        // 放大接收缓冲以逼近链路真实能力
        boost::system::error_code secc;
        relay.set_option(net::socket_base::receive_buffer_size(1 << 20), secc);
        upstream.set_option(net::socket_base::receive_buffer_size(1 << 20), secc);
        client.bind(net::ip::udp::endpoint(net::ip::address_v4::loopback(), 0));
        relay.bind(net::ip::udp::endpoint(net::ip::address_v4::loopback(), 0));
        upstream.bind(net::ip::udp::endpoint(net::ip::address_v4::loopback(), 0));

        const auto client_ep = client.local_endpoint();
        const auto relay_ep = relay.local_endpoint();
        const auto upstream_ep = upstream.local_endpoint();

        // 中继转发：client → relay → upstream（loopback 逐跳）
        net::co_spawn(ex, [&]() -> net::awaitable<void>
                      {
            memory::vector<std::byte> buf(sc.dgram + 8, memory::effective_mr(memory::system::local_pool()));
            while (!stop.load(std::memory_order_relaxed))
            {
                net::ip::udp::endpoint from;
                std::size_t n = 0;
                boost::system::error_code sec;
                n = co_await relay.async_receive_from(net::buffer(buf.data(), buf.size()), from,
                                                      net::redirect_error(net::use_awaitable, sec));
                if (sec || n == 0)
                {
                    co_return;
                }
                co_await relay.async_send_to(net::buffer(buf.data(), n), upstream_ep,
                                              net::redirect_error(net::use_awaitable, sec));
            } }, net::detached);

        // 上游：接收并校验长度 + 序号
        net::co_spawn(ex, [&]() -> net::awaitable<void>
                      {
            memory::vector<std::byte> buf(sc.dgram + 8, memory::effective_mr(memory::system::local_pool()));
            std::uint64_t expect = 0;
            while (!stop.load(std::memory_order_relaxed))
            {
                net::ip::udp::endpoint from;
                std::size_t n = 0;
                boost::system::error_code sec;
                n = co_await upstream.async_receive_from(net::buffer(buf.data(), buf.size()), from,
                                                         net::redirect_error(net::use_awaitable, sec));
                if (sec || n == 0)
                {
                    co_return;
                }
                if (n >= 8)
                {
                    std::uint64_t seq = 0;
                    std::memcpy(&seq, buf.data(), sizeof(seq));
                    if (seq != expect)
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                    expect = seq + 1;
                }
                received.fetch_add(1, std::memory_order_relaxed);
            } }, net::detached);

        // 客户端：持续发送「序号 + payload」
        memory::vector<std::byte> buf(sc.dgram + 8, memory::effective_mr(memory::system::local_pool()));
        std::uint64_t seq = 0;
        while (!stop.load(std::memory_order_relaxed))
        {
            std::memcpy(buf.data(), &seq, sizeof(seq));
            std::memset(buf.data() + 8, 0x5A, sc.dgram);
            boost::system::error_code sec;
            const auto sent_n = co_await client.async_send_to(
                net::buffer(buf.data(), sc.dgram + 8), relay_ep,
                net::redirect_error(net::use_awaitable, sec));
            if (sec)
            {
                if (!stop.load(std::memory_order_relaxed))
                {
                    errors.fetch_add(1, std::memory_order_relaxed);
                }
                co_return;
            }
            ++seq;
            sent.fetch_add(1, std::memory_order_relaxed);
            (void)sent_n;
        }
    }

    /**
     * @brief 运行单个 UDP 场景
     */
    auto run_udp_scenario(const udp_scenario &sc) -> udp_result
    {
        static std::vector<std::unique_ptr<net::io_context>> g_iocs;
        auto ioc_holder = std::make_unique<net::io_context>();
        auto &ioc = *ioc_holder;
        g_iocs.push_back(std::move(ioc_holder));
        std::atomic<bool> stop{false};
        std::atomic<std::uint64_t> received{0};
        std::atomic<std::uint64_t> sent{0};
        std::atomic<std::uint64_t> errors{0};

        std::exception_ptr ep;
        auto driver = [&]() -> net::awaitable<void>
        {
            const auto ex = co_await net::this_coro::executor;
            for (std::size_t i = 0; i < sc.chains; ++i)
            {
                net::co_spawn(ex, relay_chain(ex, sc, stop, received, sent, errors, i), net::detached);
            }
            co_await async_wait(ex, std::chrono::milliseconds(sc.duration_ms));
            stop.store(true, std::memory_order_release);
            co_await async_wait(ex, std::chrono::milliseconds(200));
        };
        const auto wall_start = std::chrono::steady_clock::now();
        net::co_spawn(ioc, driver(), [&](std::exception_ptr e)
                      { ep = e; });
        ioc.run_for(std::chrono::milliseconds(sc.duration_ms + 5000));
        const auto wall_end = std::chrono::steady_clock::now();

        udp_result result{};
        result.dgrams = received.load(std::memory_order_relaxed);
        result.sent = sent.load(std::memory_order_relaxed);
        result.errors = errors.load(std::memory_order_relaxed);
        result.seconds = std::chrono::duration<double>(wall_end - wall_start).count();
        result.mbps = result.dgrams * (sc.dgram + 8) * 8.0 / 1'000'000.0 / result.seconds;
        result.pps = static_cast<double>(result.dgrams) / result.seconds;
        result.loss_pct = (result.sent > 0)
                              ? (static_cast<double>(result.sent) - result.dgrams) * 100.0 / result.sent
                              : 0.0;
        // UDP 转发以「吞吐 + 丢包率」为指标，丢包是 UDP 链路的固有特征
        result.pass = (result.dgrams > 0);
        return result;
    }

    /**
     * @brief 打印表头
     */
    void PrintHeader()
    {
        std::cout << "\n======================================================================\n";
        std::cout << std::format("{:<16}{:>8}{:>8}{:>12}{:>12}{:>10}{:>8}\n",
                                 "场景", "报文", "链路", "吞吐", "包速率", "丢包率", "结果");
        std::cout << "----------------------------------------------------------------------\n";
    }

    /**
     * @brief 打印单行
     */
    void PrintRow(const udp_scenario &sc, const udp_result &r)
    {
        std::cout << std::format("{:<16}{:>7}B{:>8}{:>11.1f}M{:>12.0f}{:>7.2f}%{:>8}\n",
                                 sc.name, sc.dgram, sc.chains,
                                 r.mbps, r.pps, r.loss_pct,
                                 (r.pass ? "PASS" : "FAIL"));
    }

} // namespace

int main(const int argc, char **argv)
{
    (void)argc;
    (void)argv;

#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif

    memory::system::enable_pooling();

    std::cout << "========================================\n";
    std::cout << "  Prism UDP 数据报中继压力测试\n";
    std::cout << "  控制变量法: 报文大小 × 并发链路\n";
    std::cout << "========================================\n";

    const std::vector<udp_scenario> scenarios = {
        udp_scenario{.name = "U1 小包64B", .dgram = 64},
        udp_scenario{.name = "U2 信令512B", .dgram = 512},
        udp_scenario{.name = "U3 媒体4K", .dgram = 4096},
        udp_scenario{.name = "U4 大包64K", .dgram = 65499},
        udp_scenario{.name = "U5 双链512B", .dgram = 512, .chains = 2},
        udp_scenario{.name = "U6 四链512B", .dgram = 512, .chains = 4},
    };

    PrintHeader();

    std::size_t failed = 0;
    for (const auto &sc : scenarios)
    {
        const auto result = run_udp_scenario(sc);
        PrintRow(sc, result);
        if (!result.pass)
        {
            ++failed;
        }
    }

    std::cout << "======================================================================\n";
    std::cout << std::format("完成: {} 个场景, {} 个失败\n\n", scenarios.size(), failed);
    std::fflush(nullptr);
    std::quick_exit(failed == 0 ? 0 : 1);
}
