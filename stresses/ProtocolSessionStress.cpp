/**
 * @file ProtocolSessionStress.cpp
 * @brief 多协议完整会话压力测试
 * @details 控制变量法：固定单连接、64MB 数据量，变量 = 协议类型 × 块大小。
 * 每个协议走完整握手（client.connect / server.accept）后进入 passthrough 直通，
 * 使用统一 bench 框架测量吞吐（MB/s）与回环延迟（us，p50/p95/p99）。
 * 覆盖：trojan（TLS 协议层语义）、vless（无加密）、shadowsocks2022（AEAD 加密）。
 */

#include <prism/foundation/memory/pool.hpp>

#include <common/core/transport/bench.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/trojan/trojan.hpp>
#include <common/vless/vless.hpp>
#include <common/shadowsocks2022/shadowsocks2022.hpp>

#include <boost/asio.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace net = boost::asio;
namespace memory = psm::memory;
using namespace psmtest;

namespace
{

    /**
     * @brief 场景定义（控制变量法的单变量描述）
     */
    struct session_scenario
    {
        std::string name;            ///< 场景名称
        std::size_t block{65536};    ///< 块大小
        std::size_t total{64ULL * 1024 * 1024}; ///< 传输总量
    };

    /**
     * @brief 会话结果
     */
    struct session_result
    {
        double mbps{0};              ///< 吞吐
        double avg_us{0};            ///< 平均延迟 us
        double p50_us{0};
        double p95_us{0};
        double p99_us{0};
        bool pass{false};
    };

    /**
     * @brief 建立本地 socket 对（psmtest::socket_stream）
     */
    auto make_socket_pair(net::any_io_executor ex)
        -> net::awaitable<std::pair<socket_stream, socket_stream>>
    {
        net::ip::tcp::acceptor acceptor(ex, net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
        auto client_socket = net::ip::tcp::socket(ex);
        co_await client_socket.async_connect(acceptor.local_endpoint(), net::use_awaitable);
        auto server_socket = co_await acceptor.async_accept(net::use_awaitable);
        co_return std::make_pair(socket_stream(std::move(client_socket)),
                                 socket_stream(std::move(server_socket)));
    }

    /**
     * @brief 通用会话运行器：握手 → 回显 → 吞吐 + 延迟
     */
    template <typename Client, typename Server, typename Message>
    auto run_protocol_case(net::io_context &ioc, Client &cl, Server &sv,
                           Message &msg, const session_scenario &sc)
        -> net::awaitable<session_result>
    {
        session_result result{};
        auto [client_raw, server_raw] = co_await make_socket_pair(ioc.get_executor());

        // 服务端接受并回显
        std::exception_ptr server_ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
                      {
            Message srv_msg{};
            auto s = co_await sv.accept(server_raw, srv_msg);
            if (!s)
                co_return;
            std::array<std::uint8_t, 131072> buf{};
            while (true)
            {
                const auto n = co_await s->read_some(buf);
                if (n == 0)
                    break;
                (void)co_await s->write_all(std::span<const std::uint8_t>(buf.data(), n));
            }
            co_await s->close(); },
                      [&](std::exception_ptr e)
                      { server_ep = e; });

        auto client_stream = co_await cl.open(client_raw, msg);
        if (!client_stream)
        {
            result.pass = false;
            co_return result;
        }

        bench_options opt;
        opt.total = sc.total;
        opt.block = sc.block;
        auto tp = co_await bench_throughput(*client_stream, *client_stream, opt);

        // 延迟：新连接测量（bench_throughput 结束后发送流已关闭）
        auto [lat_client_raw, lat_server_raw] = co_await make_socket_pair(ioc.get_executor());
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
                      {
            Message lat_msg{};
            auto s = co_await sv.accept(lat_server_raw, lat_msg);
            if (!s)
                co_return;
            std::array<std::uint8_t, 131072> buf{};
            while (true)
            {
                const auto n = co_await s->read_some(buf);
                if (n == 0)
                    break;
                (void)co_await s->write_all(std::span<const std::uint8_t>(buf.data(), n));
            }
            co_await s->close(); },
                      net::detached);
        auto lat_stream = co_await cl.open(lat_client_raw, msg);
        if (lat_stream)
        {
            opt.rounds = 1000;
            opt.block = 4096;
            opt.external_echo = true;
            auto lat = co_await bench_latency(*lat_stream, *lat_stream, opt);
            result.avg_us = lat.avg_ms * 1000.0;
            result.p50_us = lat.p50_ms * 1000.0;
            result.p95_us = lat.p95_ms * 1000.0;
            result.p99_us = lat.p99_ms * 1000.0;
            co_await lat_stream->close();
        }
        lat_client_raw.close();
        lat_server_raw.close();

        co_await client_stream->close();
        client_raw.close();
        server_raw.close();

        result.mbps = tp.mbps;
        result.pass = (tp.bytes > 0);
        co_return result;
    }

    // 模板辅助：trojan / vless / ss2022 各自的消息与客户端配置
    auto make_trojan_msg() -> trojan::message
    {
        trojan::message msg{};
        msg.dst = trojan::address{trojan::address_type::ipv4, "127.0.0.1", 443};
        msg.valid = true;
        return msg;
    }

    auto make_vless_msg() -> vless::message
    {
        vless::message msg{};
        // uuid 全零，与 vless::client({})/server({}) 默认配置匹配
        msg.uuid = {};
        msg.cmd = vless::cmd_tcp;
        msg.dst = vless::address{vless::address_type::ipv4, "127.0.0.1", 443};
        msg.valid = true;
        return msg;
    }

    auto make_ss2022_msg() -> shadowsocks2022::message
    {
        shadowsocks2022::message msg{};
        msg.dst = shadowsocks2022::address{shadowsocks2022::address_type::ipv4, "127.0.0.1", 443};
        msg.valid = true;
        return msg;
    }

    /**
     * @brief 打印表头
     */
    void PrintHeader()
    {
        std::cout << "\n====================================================================================\n";
        std::cout << std::format("{:<14}{:>8}{:>12}{:>10}{:>10}{:>10}{:>8}\n",
                                 "协议", "块", "吞吐", "平均", "p50", "p99", "结果");
        std::cout << std::format("{:<14}{:>8}{:>12}{:>10}{:>10}{:>10}{:>8}\n",
                                 "", "", "MB/s", "us", "us", "us", "");
        std::cout << "------------------------------------------------------------------------------------\n";
    }

    /**
     * @brief 打印单行
     */
    void PrintRow(const session_scenario &sc, const session_result &r)
    {
        std::cout << std::format("{:<14}{:>7}K{}{:>11.1f}{}{:>9.1f}{}{:>9.1f}{}{:>9.1f}{}{:>8}\n",
                                 sc.name, sc.block / 1024, "", r.mbps, "",
                                 r.avg_us, "", r.p50_us, "", r.p99_us, "",
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
    std::cout << "  Prism 多协议会话压力测试\n";
    std::cout << "  控制变量法: 协议 × 块大小\n";
    std::cout << "  固定: 单连接 / 64MB 传输 / 1000 轮延迟\n";
    std::cout << "========================================\n";

    // 场景矩阵：协议(3) × 块大小(2)
    const std::vector<session_scenario> scenarios = {
        session_scenario{.name = "trojan-64K", .block = 65536},
        session_scenario{.name = "trojan-16K", .block = 16384},
        session_scenario{.name = "vless-64K", .block = 65536},
        session_scenario{.name = "vless-16K", .block = 16384},
        session_scenario{.name = "ss2022-64K", .block = 65536},
        session_scenario{.name = "ss2022-16K", .block = 16384},
    };

    PrintHeader();

    std::size_t failed = 0;
    std::size_t case_id = 0;
    for (const auto &sc : scenarios)
    {
        net::io_context ioc;

        session_result result{};
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            if (sc.name.rfind("trojan", 0) == 0)
            {
                trojan::client cl({.password = "test_password"});
                trojan::server sv({.password = "test_password"});
                auto msg = make_trojan_msg();
                result = co_await run_protocol_case(ioc, cl, sv, msg, sc);
            }
            else if (sc.name.rfind("vless", 0) == 0)
            {
                vless::client cl({});
                vless::server sv({});
                auto msg = make_vless_msg();
                result = co_await run_protocol_case(ioc, cl, sv, msg, sc);
            }
            else
            {
                shadowsocks2022::client cl({});
                shadowsocks2022::server sv({});
                auto msg = make_ss2022_msg();
                result = co_await run_protocol_case(ioc, cl, sv, msg, sc);
            }
        };
        net::co_spawn(ioc, coro(), [&](std::exception_ptr e)
                      { ep = e; });
        ioc.run_for(std::chrono::seconds(30));

        PrintRow(sc, result);
        if (!result.pass)
        {
            ++failed;
            std::cerr << "  !!! " << sc.name << " failed !!!\n";
        }
        ++case_id;
        (void)case_id;
    }

    std::cout << "====================================================================================\n";
    std::cout << std::format("完成: {} 个场景, {} 个失败\n\n", scenarios.size(), failed);
    std::fflush(nullptr);
    std::quick_exit(failed == 0 ? 0 : 1);
}
