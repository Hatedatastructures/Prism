#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <forward-engine/transformer.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace http = boost::beast::http;
namespace beast = boost::beast;
using tcp = net::ip::tcp;

std::mutex g_log_mutex;

template <typename... Args>
void safe_log(Args &&...args)
{
    std::lock_guard<std::mutex> lock(g_log_mutex);
    (std::cout << ... << std::forward<Args>(args)) << std::endl;
}

// 目标地址结构
struct target_entry
{
    std::string domain;
    std::string port;
};

// Glaze JSON 绑定
template <>
struct glz::meta<target_entry>
{
    using T = target_entry;
    static constexpr auto value = glz::object("domain", &T::domain, "port", &T::port);
};

struct stress_config
{
    std::string proxy_host = "127.0.0.1";
    std::uint16_t proxy_port = 8081;
    std::string address_file = R"(C:\Users\C1373\Desktop\code\Xray-core\forward-engine\test\address.json)";
    std::string request_path = "/1m";
    std::string user_agent =
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Mobile Safari/537.36";
    std::size_t total_requests = 1000000;
    std::size_t concurrency = 2000;
    int duration_sec = 60;
    bool enable_http = true;
    bool enable_https = true;
    std::size_t max_handles_per_worker = 0;
    int connect_timeout_sec = 10;
    int request_timeout_sec = 120;
    int reconnect_delay_ms = 100;
    bool debug_output = false;
};

struct stress_stats
{
    std::atomic<std::size_t> total_requests{0};
    std::atomic<std::size_t> success_requests{0};
    std::atomic<std::size_t> failed_requests{0};
    std::atomic<std::size_t> bytes_received{0};
    std::atomic<std::size_t> connection_errors{0};
    std::atomic<std::size_t> timeout_errors{0};
    std::atomic<std::size_t> reconnects{0};
    std::atomic<std::size_t> protocol_errors{0};
    std::atomic<std::uint64_t> total_latency_ms{0};
    std::atomic<std::uint64_t> min_latency_ms{UINT64_MAX};
    std::atomic<std::uint64_t> max_latency_ms{0};
};

std::atomic<std::int64_t> active_connections{0}; // 使用有符号数以便检测下溢

// 获取系统最大句柄数 (Windows 模拟)
std::size_t get_max_system_handles()
{
    // Windows 下句柄限制较宽松，但为了安全起见，限制在 16384
    return 16384;
}

// 计算安全并发数
[[nodiscard]] std::size_t calculate_safe_concurrency(const stress_config &config)
{
    const auto max_handles = get_max_system_handles();
    // 预留一部分句柄给系统和其他进程
    const auto max_handles_per_process = max_handles * 0.7;

    if (config.max_handles_per_worker > 0)
    {
        return std::min(config.concurrency, config.max_handles_per_worker);
    }

    // 每个连接可能占用 1-2 个 socket (代理连接)
    const auto safe_concurrency = std::min(
        config.concurrency,
        static_cast<std::size_t>(max_handles_per_process / 2));

    std::cout << "系统最大句柄数: " << max_handles << ", 安全并发数: " << safe_concurrency << std::endl;
    return safe_concurrency;
}

class stress_client
{
public:
    stress_client(const stress_config &config, const std::vector<target_entry> &targets)
        : config_(config), targets_(targets)
    {
        // 自动调整并发数
        config_.concurrency = calculate_safe_concurrency(config);
    }

    void run()
    {
        safe_log("压测配置: ");
        safe_log("  代理地址: ", config_.proxy_host, ":", config_.proxy_port);
        safe_log("  目标数量: ", targets_.size());
        safe_log("  总请求数: ", config_.total_requests);
        safe_log("  并发连接: ", config_.concurrency);
        safe_log("  请求路径: ", config_.request_path);
        safe_log("  连接超时: ", config_.connect_timeout_sec, "秒");
        safe_log("  请求超时: ", config_.request_timeout_sec, "秒");
        safe_log("  重连延迟: ", config_.reconnect_delay_ms, "毫秒");
        safe_log("  调试输出: ", config_.debug_output ? "开启" : "关闭");

        net::co_spawn(ioc_, print_stats(), net::detached);

        for (std::size_t i = 0; i < config_.concurrency; ++i)
        {
            net::co_spawn(ioc_, run_worker(i), net::detached);
        }

        std::vector<std::thread> threads;
        int thread_count = std::thread::hardware_concurrency();
        safe_log("  工作线程: ", thread_count);

        threads.reserve(thread_count);
        for (int i = 0; i < thread_count; ++i)
        {
            threads.emplace_back([this]
                                 { ioc_.run(); });
        }

        for (auto &t : threads)
        {
            if (t.joinable())
                t.join();
        }
    }

private:
    net::io_context ioc_;
    stress_config config_;
    std::vector<target_entry> targets_;
    stress_stats stats_;

    // 随机数生成器
    std::mt19937 rng_{std::random_device{}()};

    net::awaitable<void> print_stats()
    {
        auto timer = net::steady_timer(co_await net::this_coro::executor);
        auto start_time = std::chrono::steady_clock::now();
        std::size_t last_requests = 0;
        std::size_t last_bytes = 0;

        for (;;)
        {
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(net::use_awaitable);

            auto now = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();

            auto total = stats_.total_requests.load(std::memory_order_relaxed);
            auto success = stats_.success_requests.load(std::memory_order_relaxed);
            auto failed = stats_.failed_requests.load(std::memory_order_relaxed);
            auto bytes = stats_.bytes_received.load(std::memory_order_relaxed);
            auto active = active_connections.load(std::memory_order_relaxed);
            auto timeout_err = stats_.timeout_errors.load(std::memory_order_relaxed);
            auto conn_err = stats_.connection_errors.load(std::memory_order_relaxed);
            auto proto_err = stats_.protocol_errors.load(std::memory_order_relaxed);
            auto total_latency = stats_.total_latency_ms.load(std::memory_order_relaxed);
            auto min_latency = stats_.min_latency_ms.load(std::memory_order_relaxed);
            auto max_latency = stats_.max_latency_ms.load(std::memory_order_relaxed);

            auto current_requests = total - last_requests;
            auto current_bytes = bytes - last_bytes;

            double qps = current_requests > 0 ? (double)current_requests : 0.0;
            double mbps = (double)current_bytes * 8 / 1024 / 1024;

            double success_rate = total > 0 ? (double)success / total * 100.0 : 0.0;

            double avg_latency = success > 0 ? (double)total_latency / success : 0.0;
            std::uint64_t display_min = min_latency == UINT64_MAX ? 0 : min_latency;

            safe_log("[实时统计] ",
                     "QPS: ", qps, " | ",
                     "带宽: ", mbps, " Mbps | ",
                     "成功率: ", success_rate, "% | ",
                     "活跃连接: ", active, " | ",
                     "总流量: ", bytes / 1024 / 1024, " MB | ",
                     "延迟: avg=", avg_latency, "ms, min=", display_min, "ms, max=", max_latency, "ms | ",
                     "错误: timeout=", timeout_err, ", conn=", conn_err, ", proto=", proto_err);

            last_requests = total;
            last_bytes = bytes;

            if (total >= config_.total_requests)
            {
                ioc_.stop();
                break;
            }
        }
    }

    net::awaitable<void> run_worker(std::size_t worker_id)
    {
        // 每个 worker 维护一个持久连接，直到需要切换目标
        // 这里简化逻辑：每个 worker 不断发送请求，保持连接复用

        tcp::resolver resolver(co_await net::this_coro::executor);
        beast::tcp_stream stream(co_await net::this_coro::executor);

        // 随机选择一个目标
        std::uniform_int_distribution<std::size_t> dist(0, targets_.size() - 1);

        bool is_connected = false;

        for (;;)
        {
            if (stats_.total_requests.load(std::memory_order_relaxed) >= config_.total_requests)
                co_return;

            auto &target = targets_[dist(rng_)]; // 简化：每次请求可能切换目标，但为了 keep-alive 最好保持
            // 为了测试 keep-alive，我们暂时不切换目标，除非连接断开

            if (!is_connected)
            {
                boost::system::error_code ec;

                auto const results = co_await resolver.async_resolve(config_.proxy_host, std::to_string(config_.proxy_port), net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    stats_.connection_errors.fetch_add(1, std::memory_order_relaxed);
                    co_await async_sleep(std::chrono::milliseconds(config_.reconnect_delay_ms));
                    continue;
                }

                stream.expires_after(std::chrono::seconds(config_.connect_timeout_sec));
                co_await stream.async_connect(results, net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    stats_.connection_errors.fetch_add(1, std::memory_order_relaxed);
                    co_await async_sleep(std::chrono::milliseconds(config_.reconnect_delay_ms));
                    continue;
                }

                active_connections.fetch_add(1, std::memory_order_relaxed);
                stats_.reconnects.fetch_add(1, std::memory_order_relaxed);
                is_connected = true;
                stream.socket().set_option(tcp::no_delay(true));
            }

            // 发送 HTTP 请求
            // 注意：HTTP 代理请求需要使用绝对 URI
            std::string full_target = "http://" + target.domain + ":" + target.port + config_.request_path;
            http::request<http::string_body> req{http::verb::get, full_target, 11};
            req.set(http::field::host, target.domain + ":" + target.port);
            req.set(http::field::user_agent, config_.user_agent);
            req.keep_alive(true);                                 // 强制 Keep-Alive
            req.set(http::field::proxy_connection, "keep-alive"); // 代理连接保持

            boost::system::error_code ec;
            stream.expires_after(std::chrono::seconds(config_.request_timeout_sec));

            if (config_.debug_output)
            {
                static std::atomic<int> send_debug_counter{0};
                if (send_debug_counter.fetch_add(1, std::memory_order_relaxed) % 100 == 0)
                {
                    safe_log("[调试发送] 目标: ", full_target, ", Host: ", target.domain + ":" + target.port);
                }
            }

            co_await http::async_write(stream, req, net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                safe_log("[错误] 发送请求失败: ", ec.message());
                handle_error(stream, is_connected, ec);
                continue;
            }

            beast::flat_buffer buffer{2 * 1024 * 1024};

            http::response<http::string_body> res;

            if (config_.debug_output)
            {
                static std::atomic<int> read_start_debug_counter{0};
                if (read_start_debug_counter.fetch_add(1, std::memory_order_relaxed) % 100 == 0)
                {
                    safe_log("[调试读取] 开始读取响应，缓冲区大小: ", buffer.size(), " bytes");
                }
            }

            auto request_start = std::chrono::steady_clock::now();

            co_await http::async_read(stream, buffer, res, net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                safe_log("[错误] 读取响应失败: ", ec.message());
                handle_error(stream, is_connected, ec);
                continue;
            }

            auto request_end = std::chrono::steady_clock::now();
            auto latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(request_end - request_start).count();

            auto body_size = res.body().size();
            if (config_.debug_output)
            {
                static std::atomic<int> debug_counter{0};
                if (debug_counter.fetch_add(1, std::memory_order_relaxed) % 100 == 0)
                {
                    safe_log("[调试] 响应状态: ", res.result_int(),
                             ", Content-Length: ", (res.find(http::field::content_length) != res.end() ? std::string(res[http::field::content_length]) : "无"),
                             ", 实际body大小: ", body_size, " bytes",
                             ", 延迟: ", latency_ms, " ms");
                }
            }

            stats_.total_requests.fetch_add(1, std::memory_order_relaxed);
            if (res.result() == http::status::ok)
            {
                stats_.success_requests.fetch_add(1, std::memory_order_relaxed);
                stats_.bytes_received.fetch_add(body_size, std::memory_order_relaxed);

                stats_.total_latency_ms.fetch_add(latency_ms, std::memory_order_relaxed);

                std::uint64_t current_min = stats_.min_latency_ms.load(std::memory_order_relaxed);
                while (latency_ms < current_min &&
                       !stats_.min_latency_ms.compare_exchange_weak(current_min, latency_ms, std::memory_order_relaxed))
                {
                }

                std::uint64_t current_max = stats_.max_latency_ms.load(std::memory_order_relaxed);
                while (latency_ms > current_max &&
                       !stats_.max_latency_ms.compare_exchange_weak(current_max, latency_ms, std::memory_order_relaxed))
                {
                }
            }
            else
            {
                stats_.failed_requests.fetch_add(1, std::memory_order_relaxed);
                stats_.protocol_errors.fetch_add(1, std::memory_order_relaxed);
            }

            if (!res.keep_alive())
            {
                handle_disconnect(stream, is_connected);
                co_await async_sleep(std::chrono::milliseconds(config_.reconnect_delay_ms));
            }
        }
    }

    void handle_error(beast::tcp_stream &stream, bool &is_connected, const boost::system::error_code &ec)
    {
        stats_.failed_requests.fetch_add(1, std::memory_order_relaxed);

        if (ec == boost::beast::error::timeout ||
            ec == net::error::timed_out ||
            ec.message().find("timeout") != std::string::npos)
        {
            stats_.timeout_errors.fetch_add(1, std::memory_order_relaxed);
        }
        else if (ec == net::error::connection_reset ||
                 ec == net::error::connection_aborted ||
                 ec == net::error::broken_pipe ||
                 ec == net::error::not_connected ||
                 ec == net::error::eof ||
                 ec == http::error::end_of_stream)
        {
            stats_.connection_errors.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            stats_.protocol_errors.fetch_add(1, std::memory_order_relaxed);
        }

        handle_disconnect(stream, is_connected);
    }

    void handle_disconnect(beast::tcp_stream &stream, bool &is_connected)
    {
        if (is_connected)
        {
            boost::system::error_code ec;
            stream.socket().shutdown(tcp::socket::shutdown_both, ec);
            stream.close();
            active_connections.fetch_sub(1, std::memory_order_relaxed);
            is_connected = false;
        }
    }

    net::awaitable<void> async_sleep(std::chrono::milliseconds duration)
    {
        net::steady_timer timer(co_await net::this_coro::executor);
        timer.expires_after(duration);
        co_await timer.async_wait(net::use_awaitable);
    }
};

int main()
{
    SetConsoleOutputCP(CP_UTF8);

    stress_config config;

    std::vector<target_entry> targets;
    std::ifstream file(config.address_file);
    if (file.is_open())
    {
        std::string json_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        auto ec = glz::read_json(targets, json_content);
        if (ec)
        {
            safe_log("解析 address.json 失败");
            targets.push_back({"127.0.0.1", "8000"});
        }
    }
    else
    {
        safe_log("无法打开 address.json，使用默认目标 127.0.0.1:8000");
        targets.push_back({"127.0.0.1", "8000"});
    }

    if (targets.empty())
    {
        targets.push_back({"127.0.0.1", "8000"});
    }

    try
    {
        stress_client client(config, targets);
        client.run();
    }
    catch (const std::exception &e)
    {
        safe_log("发生异常: ", e.what());
    }

    return 0;
}
