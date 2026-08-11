/**
 * @file TlsTunnelStress.cpp
 * @brief TLS 加密隧道端到端压力测试
 * @details 控制变量法：变量 = TLS 版本(1.2/1.3) × 并发连接数 × 块大小。
 * 三段架构（手机端 / TLS 隧道 / 上游端）与真实代理一致：
 * 隧道两侧分别以 TLS server / client 角色握手（encrypted transport），
 * 测量加密转发的真实吞吐与延迟，与未加密 TunnelStress 基线对比加密开销。
 */

#include <prism/net/connection/tunnel/tunnel_relay.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/adapter/connector.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/diagnose/diagnose.hpp>

#include "StressUtil.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

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

namespace transport = psm::transport;
namespace memory = psm::memory;
namespace diagnose = psm::diagnose;
using namespace psm::stress;

namespace
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @brief TLS 场景定义
     */
    struct tls_scenario
    {
        std::string name;                    ///< 场景名称
        bool tls13{true};                    ///< 是否 TLS1.3（false = 1.2）
        std::size_t connections{1};          ///< 并发连接数
        std::size_t block{65536};            ///< 块大小
        std::size_t duration_ms{3000};       ///< 持续时间
    };

    /**
     * @brief 单连接统计
     */
    struct link_stats
    {
        std::atomic<std::uint64_t> received{0};
        std::atomic<std::uint64_t> errors{0};
        std::atomic<bool> exited{false};
    };

    /**
     * @brief 结果
     */
    struct tls_result
    {
        std::uint64_t total_bytes{0};
        std::uint64_t errors{0};
        double seconds{0};
        double mbps{0};
        double per_conn_mbps{0};
        bool pass{false};
    };

    /**
     * @brief 单连接三段结构
     */
    struct harness
    {
        transport::shared_transmission phone_tx;      ///< 手机端
        transport::shared_transmission upstream_tx;   ///< 上游端
        transport::shared_transmission tls_server;    ///< TLS server 侧（隧道 A）
        transport::shared_transmission tls_client;    ///< TLS client 侧（隧道 B）
        link_stats stats;
    };

    /**
     * @brief 构造 TLS 上下文
     */
    auto make_server_ctx(const bool tls13) -> ssl::context
    {
        ssl::context ctx(ssl::context::tls_server);
        boost::system::error_code ec;
        ctx.use_certificate_chain_file("I:\\code\\Prism\\cert.pem", ec);
        if (!ec)
        {
            ctx.use_private_key_file("I:\\code\\Prism\\key.pem", ssl::context::pem, ec);
        }
        unsigned long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
        if (tls13)
        {
            opts |= SSL_OP_NO_TLSv1_2;
        }
        else
        {
            opts |= SSL_OP_NO_TLSv1_3;
        }
        ctx.set_options(opts, ec);
        return ctx;
    }

    auto make_client_ctx(const bool tls13) -> ssl::context
    {
        ssl::context ctx(ssl::context::tls_client);
        ctx.set_verify_mode(ssl::verify_none);
        unsigned long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
        if (tls13)
        {
            opts |= SSL_OP_NO_TLSv1_2;
        }
        else
        {
            opts |= SSL_OP_NO_TLSv1_3;
        }
        boost::system::error_code ec;
        ctx.set_options(opts, ec);
        return ctx;
    }

    /**
     * @brief 上游流量写入协程
     */
    auto writer_coro(transport::shared_transmission tx, const tls_scenario &sc,
                     std::span<const std::byte> pool, const std::atomic<bool> &stop,
                     link_stats &stats) -> net::awaitable<void>
    {
        std::error_code ec;
        std::uint64_t seq = 0;
        memory::vector<std::byte> packet(16 + sc.block, memory::effective_mr(memory::system::local_pool()));

        while (!stop.load(std::memory_order_relaxed))
        {
            const auto length = static_cast<std::uint64_t>(sc.block);
            const auto current_seq = seq++;
            std::memcpy(packet.data(), &length, sizeof(length));
            std::memcpy(packet.data() + 8, &current_seq, sizeof(current_seq));
            std::memcpy(packet.data() + 16, pool.data(), sc.block);

            const auto n = co_await transport::async_write(*tx, std::span(packet).first(16 + sc.block), ec);
            if (ec)
            {
                // stop 之后的错误（cancel/close/aborted）属正常收尾，不计
                if (!stop.load(std::memory_order_relaxed))
                {
                    stats.errors.fetch_add(1, std::memory_order_relaxed);
                }
                co_return;
            }
            if (n == 0)
            {
                co_return;
            }
        }
    }

    /**
     * @brief 手机端校验协程
     */
    auto reader_coro(transport::shared_transmission tx, link_stats &stats) -> net::awaitable<void>
    {
        std::error_code ec;
        std::uint64_t expect_seq = 0;
        std::array<std::uint64_t, 2> header{};
        memory::vector<std::byte> discard(16, memory::effective_mr(memory::system::local_pool()));

        while (true)
        {
            const auto header_n = co_await transport::async_read(
                *tx, std::span(reinterpret_cast<std::byte *>(header.data()), sizeof(header)), ec);
            if (ec || header_n == 0)
            {
                co_return;
            }
            const auto length = header[0];
            if (length == 0 || length > 131072)
            {
                stats.errors.fetch_add(1, std::memory_order_relaxed);
                co_return;
            }
            if (discard.size() < length)
            {
                discard.resize(length);
            }
            const auto body_n = co_await transport::async_read(*tx, std::span(discard).first(length), ec);
            if (ec || body_n == 0)
            {
                co_return;
            }
            if (header[1] != expect_seq)
            {
                stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
            expect_seq = header[1] + 1;
            stats.received.fetch_add(header_n + body_n, std::memory_order_relaxed);
        }
    }

    /**
     * @brief 隧道转发协程（TLS 包装）
     */
    auto tunnel_coro(const tls_scenario &sc, harness &h) -> net::awaitable<void>
    {
        psm::connect::tunnel_options opts{h.tls_server, h.tls_client, static_cast<std::uint32_t>(sc.block * 2),
                                          psm::connect::write_policy::complete};
        opts.trace = std::make_shared<diagnose::context>();
        co_await psm::connect::tunnel_relay(std::move(opts)).run();
    }

    /**
     * @brief 协程退出计数包装
     */
    auto spawn_guard(net::any_io_executor ex, net::awaitable<void> coro, std::shared_ptr<harness> h)
    {
        net::co_spawn(
            ex, std::move(coro),
            [h](std::exception_ptr)
            {
                h->stats.exited.store(true, std::memory_order_release);
            });
    }

    /**
     * @brief 运行单个 TLS 场景
     */
    auto run_tls_scenario(const tls_scenario &sc) -> tls_result
    {
        static std::vector<std::unique_ptr<net::io_context>> g_iocs;
        auto ioc_holder = std::make_unique<net::io_context>();
        auto &ioc = *ioc_holder;
        g_iocs.push_back(std::move(ioc_holder));
        std::atomic<bool> stop{false};
        std::vector<std::shared_ptr<harness>> harnesses;
        harnesses.reserve(sc.connections);
        for (std::size_t i = 0; i < sc.connections; ++i)
        {
            harnesses.push_back(std::make_shared<harness>());
        }
        auto pool = make_payload_pool(sc.block > 4096 ? sc.block : 4096);

        std::exception_ptr ep;
        auto driver = [&]() -> net::awaitable<void>
        {
            const auto ex = co_await net::this_coro::executor;
            auto server_ctx = make_server_ctx(sc.tls13);
            auto client_ctx = make_client_ctx(sc.tls13);

            for (auto &h : harnesses)
            {
                auto [phone_sock, proxy_client_sock] = co_await make_socket_pair(ex);
                auto [upstream_sock, proxy_server_sock] = co_await make_socket_pair(ex);
                // TLS 只发生在「手机 ↔ 代理」这对 socket 上（与真实代理一致），
                // 「代理 ↔ 上游」为明文；隧道在加密传输与明文传输之间双向转发。
                auto server_ssl = std::make_shared<ssl::stream<transport::connector>>(
                    transport::connector(transport::make_reliable(std::move(proxy_client_sock))), server_ctx);
                auto phone_ssl = std::make_shared<ssl::stream<transport::connector>>(
                    transport::connector(transport::make_reliable(std::move(phone_sock))), client_ctx);

                // TLS 握手：server / client 并行发起
                std::exception_ptr handshake_ep;
                net::co_spawn(ex, [server_ssl]() -> net::awaitable<void>
                              {
                    boost::system::error_code sec;
                    co_await server_ssl->async_handshake(ssl::stream_base::server,
                                                         net::redirect_error(net::use_awaitable, sec)); },
                              [&](std::exception_ptr e) { handshake_ep = e; });
                boost::system::error_code sec;
                co_await phone_ssl->async_handshake(ssl::stream_base::client,
                                                    net::redirect_error(net::use_awaitable, sec));

                // 手机侧 = TLS 加密传输（读解密数据）；上游侧 = 明文传输
                h->phone_tx = std::make_shared<transport::encrypted>(phone_ssl);
                h->upstream_tx = transport::make_reliable(std::move(upstream_sock));
                h->tls_server = std::make_shared<transport::encrypted>(server_ssl);
                h->tls_client = transport::make_reliable(std::move(proxy_server_sock));

                spawn_guard(ex, writer_coro(h->upstream_tx, sc, pool, stop, h->stats), h);
                spawn_guard(ex, reader_coro(h->phone_tx, h->stats), h);
                spawn_guard(ex, tunnel_coro(sc, *h), h);
            }

            co_await async_wait(ex, std::chrono::milliseconds(sc.duration_ms));
            stop.store(true, std::memory_order_release);

            for (auto &h : harnesses)
            {
                h->phone_tx->close();
                h->upstream_tx->close();
                h->tls_server->close();
                h->tls_client->close();
            }

            for (std::size_t wait_ms = 0; wait_ms < 30000; wait_ms += 20)
            {
                bool all_exited = true;
                for (auto &h : harnesses)
                {
                    if (!h->stats.exited.load(std::memory_order_acquire))
                    {
                        all_exited = false;
                        break;
                    }
                }
                if (all_exited)
                {
                    break;
                }
                co_await async_wait(ex, std::chrono::milliseconds(20));
            }
        };

        const auto wall_start = std::chrono::steady_clock::now();
        net::co_spawn(ioc, driver(), [&](std::exception_ptr e)
                      { ep = e; });
        ioc.run_for(std::chrono::milliseconds(sc.duration_ms + 30000));
        const auto wall_end = std::chrono::steady_clock::now();

        tls_result result{};
        result.seconds = std::chrono::duration<double>(wall_end - wall_start).count();
        for (const auto &h : harnesses)
        {
            result.total_bytes += h->stats.received.load(std::memory_order_relaxed);
            result.errors += h->stats.errors.load(std::memory_order_relaxed);
        }
        result.mbps = result.total_bytes * 8.0 / 1'000'000.0 / result.seconds;
        result.per_conn_mbps = result.mbps / static_cast<double>(sc.connections);
        result.pass = (result.errors == 0 && result.total_bytes > 0);

        static std::vector<std::vector<std::shared_ptr<harness>>> g_leaks;
        g_leaks.push_back(std::move(harnesses));
        return result;
    }

    /**
     * @brief 打印表头
     */
    void PrintHeader()
    {
        std::cout << "\n==================================================================================\n";
        std::cout << std::format("{:<14}{:>8}{:>8}{:>12}{:>14}{:>8}\n",
                                 "场景", "TLS", "并发", "吞吐", "单连接", "结果");
        std::cout << "----------------------------------------------------------------------------------\n";
    }

    /**
     * @brief 打印单行
     */
    void PrintRow(const tls_scenario &sc, const tls_result &r)
    {
        std::cout << std::format("{:<14}{:>8}{:>8}{:>11.1f}M{}{:>13.1f}M{}{:>8}\n",
                                 sc.name, (sc.tls13 ? "1.3" : "1.2"), sc.connections,
                                 r.mbps, "", r.per_conn_mbps, "",
                                 (r.pass ? "PASS" : "FAIL"));
        if (r.errors > 0)
        {
            std::cout << std::format("  !!! {} 出现 {} 个错误 !!!\n", sc.name, r.errors);
        }
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
    std::cout << "  Prism TLS 加密隧道压力测试\n";
    std::cout << "  控制变量法: TLS版本 × 并发 × 块大小\n";
    std::cout << "  对比未加密基线: TunnelStress S1/S2 (14.7G/10.6G)\n";
    std::cout << "========================================\n";

    const std::vector<tls_scenario> scenarios = {
        tls_scenario{.name = "T1 TLS1.3单连", .tls13 = true, .connections = 1},
        tls_scenario{.name = "T2 TLS1.3并发16", .tls13 = true, .connections = 16},
        tls_scenario{.name = "T3 TLS1.2单连", .tls13 = false, .connections = 1},
        tls_scenario{.name = "T4 TLS1.2并发16", .tls13 = false, .connections = 16},
        tls_scenario{.name = "T5 TLS1.3小块16K", .tls13 = true, .connections = 1, .block = 16384},
        tls_scenario{.name = "T6 TLS1.3并发64", .tls13 = true, .connections = 64},
    };

    PrintHeader();

    std::size_t failed = 0;
    for (const auto &sc : scenarios)
    {
        const auto result = run_tls_scenario(sc);
        PrintRow(sc, result);
        if (!result.pass)
        {
            ++failed;
        }
    }

    std::cout << "==================================================================================\n";
    std::cout << std::format("完成: {} 个场景, {} 个失败\n\n", scenarios.size(), failed);
    std::fflush(nullptr);
    std::quick_exit(failed == 0 ? 0 : 1);
}
