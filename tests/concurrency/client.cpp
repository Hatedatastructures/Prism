/**
 * @file client.cpp
 * @brief HTTP 压力测试客户端
 * @details 基于 Boost.Asio 协程的 HTTP 压力测试客户端，支持代理模式和直连模式。
 *          用于测试代理服务器的并发处理能力和吞吐量。
 * @author ForwardEngine Team
 * @date 2026-03-01
 */

#include <boost/asio.hpp>
#include <boost/beast/core/flat_buffer.hpp>

#include <prism/memory.hpp>
#include <prism/transformer.hpp>
#include <prism/trace.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

namespace net = boost::asio;
namespace memory = psm::memory;
using tcp = net::ip::tcp;

/**
 * @brief 将系统错误消息转换为 UTF-8
 * @param msg 系统错误消息（可能是本地编码）
 * @return UTF-8 编码的错误消息
 */
std::string ToUtf8Message(const std::string &msg)
{
    if (msg.empty())
        return msg;

    int wlen = MultiByteToWideChar(CP_ACP, 0, msg.c_str(), -1, nullptr, 0);
    if (wlen <= 0)
        return msg;

    std::wstring wmsg(wlen, 0);
    MultiByteToWideChar(CP_ACP, 0, msg.c_str(), -1, wmsg.data(), wlen);

    int u8len = WideCharToMultiByte(CP_UTF8, 0, wmsg.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (u8len <= 0)
        return msg;

    std::string u8msg(u8len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wmsg.c_str(), -1, u8msg.data(), u8len, nullptr, nullptr);

    return u8msg;
}

/**
 * @struct stress_config
 * @brief 压力测试配置
 * @details 定义压力测试的所有配置参数，包括代理服务器地址、后端目标地址和测试参数。
 */
struct stress_config
{
    std::string proxy_host = "127.0.0.1";   ///< 代理服务器地址
    std::uint16_t proxy_port = 8081;        ///< 代理服务器端口
    std::string backend_host = "127.0.0.1"; ///< 后端目标服务器地址
    std::uint16_t backend_port = 8000;      ///< 后端目标服务器端口
    std::string request_path = "/stress";   ///< 请求路径（"/" 并发模式，"/stress" 压力模式）
    std::size_t total_requests = 1000000;   ///< 总请求数
    std::size_t concurrency = 2000;         ///< 并发连接数
    int connect_timeout_sec = 10;           ///< 连接超时（秒）
    int request_timeout_sec = 30;           ///< 请求超时（秒）
    int reconnect_delay_ms = 100;           ///< 重连延迟（毫秒）
    bool debug_output = false;              ///< 调试输出开关
};

/**
 * @struct stress_stats
 * @brief 压力测试统计
 * @details 使用原子变量记录测试过程中的各项统计数据，支持多线程并发更新。
 */
struct stress_stats
{
    std::atomic<std::size_t> total_requests{0};            ///< 总请求数
    std::atomic<std::size_t> success_requests{0};          ///< 成功请求数
    std::atomic<std::size_t> failed_requests{0};           ///< 失败请求数
    std::atomic<std::size_t> bytes_received{0};            ///< 接收字节数
    std::atomic<std::size_t> connection_errors{0};         ///< 连接错误数
    std::atomic<std::size_t> timeout_errors{0};            ///< 超时错误数
    std::atomic<std::size_t> reconnects{0};                ///< 重连次数
    std::atomic<std::size_t> protocol_errors{0};           ///< 协议错误数
    std::atomic<std::uint64_t> total_latency_ms{0};        ///< 总延迟（毫秒）
    std::atomic<std::uint64_t> min_latency_ms{UINT64_MAX}; ///< 最小延迟（毫秒）
    std::atomic<std::uint64_t> max_latency_ms{0};          ///< 最大延迟（毫秒）
};

std::atomic<std::int64_t> active_connections{0}; ///< 活跃连接数

/**
 * @class client
 * @brief 压力测试客户端
 * @details 基于 Boost.Asio 协程实现的 HTTP 压力测试客户端。
 *          支持多线程并发请求，自动统计 QPS、带宽、延迟等指标。
 */
class client
{
public:
    /**
     * @brief 构造函数
     * @param config 压力测试配置
     */
    client(const stress_config &config)
        : config_(config)
    {
    }

    /**
     * @brief 运行压力测试
     * @details 启动多个工作协程和统计协程，运行压力测试直到完成。
     */
    void start()
    {
        psm::trace::info("压测配置: ");
        psm::trace::info("  代理地址: {}:{}", config_.proxy_host, config_.proxy_port);
        psm::trace::info("  后端地址: {}:{}", config_.backend_host, config_.backend_port);
        psm::trace::info("  请求路径: {}", config_.request_path);
        psm::trace::info("  总请求数: {}", config_.total_requests);
        psm::trace::info("  并发连接: {}", config_.concurrency);
        psm::trace::info("  连接超时: {}秒", config_.connect_timeout_sec);
        psm::trace::info("  请求超时: {}秒", config_.request_timeout_sec);
        psm::trace::info("  重连延迟: {}毫秒", config_.reconnect_delay_ms);
        psm::trace::info("  调试输出: {}", config_.debug_output ? "开启" : "关闭");

        net::co_spawn(ioc_, PrintStats(), net::detached);

        for (std::size_t i = 0; i < config_.concurrency; ++i)
        {
            net::co_spawn(ioc_, worker(i), net::detached);
        }

        std::vector<std::jthread> threads;
        int thread_count = std::thread::hardware_concurrency();
        psm::trace::info("  工作线程: {}", thread_count);

        threads.reserve(thread_count);
        for (int i = 0; i < thread_count; ++i)
        {
            auto func = [this]
            {
                ioc_.run();
            };
            threads.emplace_back(func);
        }

        for (auto &t : threads)
        {
            if (t.joinable())
            {
                t.join();
            }
        }
    }

private:
    net::io_context ioc_;  ///< IO 上下文
    stress_config config_; ///< 测试配置
    stress_stats stats_;   ///< 统计数据

    /**
     * @brief 打印统计信息协程
     * @details 每秒打印一次实时统计信息，包括 QPS、带宽、成功率、延迟等。
     * @return 协程任务
     */
    net::awaitable<void> PrintStats()
    {
        auto timer = net::steady_timer(co_await net::this_coro::executor);
        std::size_t last_requests = 0;
        std::size_t last_bytes = 0;

        for (;;)
        {
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(net::use_awaitable);

            auto total = stats_.total_requests.load(std::memory_order_relaxed);
            auto success = stats_.success_requests.load(std::memory_order_relaxed);
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

            psm::trace::info("[实时统计] QPS: {} | 带宽: {} Mbps | 成功率: {}% | 活跃连接: {} | 总流量: {} MB | 延迟: avg={}ms, min={}ms, max={}ms | 错误: timeout={}, conn={}, proto={}",
                             qps, mbps, success_rate, active, bytes / 1024 / 1024,
                             avg_latency, display_min, max_latency,
                             timeout_err, conn_err, proto_err);

            last_requests = total;
            last_bytes = bytes;

            if (total >= config_.total_requests)
            {
                ioc_.stop();
                break;
            }
        }
    }

    /**
     * @brief 工作协程
     * @details 每个工作协程维护一个持久连接，持续发送 HTTP 请求并接收响应。
     *          支持 "/" 并发模式和 "/stress" 压力模式。
     * @param worker_id 工作协程 ID
     * @return 协程任务
     */
    net::awaitable<void> worker(std::size_t /*worker_id*/)
    {
        auto mr = memory::current_resource();

        tcp::resolver resolver(co_await net::this_coro::executor);
        tcp::socket socket(co_await net::this_coro::executor);

        bool is_connected = false;
        bool is_stress_mode = (config_.request_path == "/stress");
        int consecutive_failures = 0;

        for (;;)
        {
            if (stats_.total_requests.load(std::memory_order_relaxed) >= config_.total_requests)
                co_return;

            if (!is_connected)
            {
                if (!co_await ConnectToProxy(resolver, socket))
                {
                    consecutive_failures++;
                    int delay_ms = CalculateBackoffDelay(consecutive_failures);
                    co_await AsyncSleep(std::chrono::milliseconds(delay_ms));
                    continue;
                }
                is_connected = true;
                consecutive_failures = 0;
            }

            boost::system::error_code ec;
            auto request_data = BuildRequest(mr);

            if (config_.debug_output)
            {
                static std::atomic<int> send_debug_counter{0};
                if (send_debug_counter.fetch_add(1, std::memory_order_relaxed) % 100 == 0)
                {
                    psm::trace::debug("[调试发送] 目标: http://{}:{}{}",
                                      config_.backend_host, config_.backend_port, config_.request_path);
                }
            }

            co_await net::async_write(socket, net::buffer(request_data), net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                psm::trace::error("[错误] 发送请求失败: {}", ec.message());
                HandleError(socket, is_connected, ec);
                continue;
            }

            auto request_start = std::chrono::steady_clock::now();

            if (is_stress_mode)
            {
                co_await HandleStressMode(socket, is_connected, mr, request_start);
            }
            else
            {
                co_await HandleNormalMode(socket, is_connected, mr, request_start);
            }
        }
    }

    /**
     * @brief 计算退避延迟（带随机抖动）
     * @param consecutive_failures 连续失败次数
     * @return 延迟毫秒数
     */
    int CalculateBackoffDelay(int consecutive_failures)
    {
        constexpr int min_delay = 100;
        constexpr int max_delay = 5000;

        if (consecutive_failures <= 0)
        {
            return min_delay;
        }

        int base_delay = min_delay * (1 << std::min(consecutive_failures, 6));
        base_delay = std::min(base_delay, max_delay);

        static thread_local std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<int> dist(0, base_delay / 2);
        return base_delay + dist(gen);
    }

    /**
     * @brief 连接代理服务器
     * @param resolver DNS 解析器
     * @param socket TCP 套接字
     * @return 连接是否成功
     */
    net::awaitable<bool> ConnectToProxy(tcp::resolver &resolver, tcp::socket &socket)
    {
        boost::system::error_code ec;

        boost::system::error_code ignore_ec;
        socket.close(ignore_ec);

        auto token = net::redirect_error(net::use_awaitable, ec);
        auto const results = co_await resolver.async_resolve(
            config_.proxy_host,
            std::to_string(config_.proxy_port),
            token);
        if (ec)
        {
            if (config_.debug_output)
            {
                psm::trace::debug("[连接] DNS 解析失败: {}", ToUtf8Message(ec.message()));
            }
            stats_.connection_errors.fetch_add(1, std::memory_order_relaxed);
            co_return false;
        }

        co_await net::async_connect(socket, results, token);
        if (ec)
        {
            if (config_.debug_output)
            {
                psm::trace::debug("[连接] 连接失败: {}", ToUtf8Message(ec.message()));
            }
            socket.close(ignore_ec);
            stats_.connection_errors.fetch_add(1, std::memory_order_relaxed);
            co_return false;
        }

        active_connections.fetch_add(1, std::memory_order_relaxed);
        stats_.reconnects.fetch_add(1, std::memory_order_relaxed);
        socket.set_option(tcp::no_delay(true));
        if (config_.debug_output)
        {
            psm::trace::debug("[连接] 连接成功");
        }
        co_return true;
    }

    /**
     * @brief 构建 HTTP 请求
     * @param mr 内存资源
     * @return 序列化后的请求数据
     */
    memory::string BuildRequest(memory::resource_pointer mr)
    {
        memory::string req(mr);
        req.append("GET http://");
        req.append(config_.backend_host);
        req.append(":");
        req.append(std::to_string(config_.backend_port));
        req.append(config_.request_path);
        req.append(" HTTP/1.1\r\n");
        req.append("Host: ");
        req.append(config_.backend_host);
        req.append(":");
        req.append(std::to_string(config_.backend_port));
        req.append("\r\n");
        req.append("Connection: keep-alive\r\n");
        req.append("\r\n");
        return req;
    }

    /**
     * @brief 处理 stress 模式
     * @details 持续读取 HTTP 响应并发送 ACK，直到连接关闭或达到总请求数。
     * @param socket TCP 套接字
     * @param is_connected 连接状态标志
     * @param mr 内存资源
     * @param request_start 请求开始时间
     */
    net::awaitable<void> HandleStressMode(tcp::socket &socket, bool &is_connected,
                                          memory::resource_pointer mr, std::chrono::steady_clock::time_point request_start)
    {
        std::array<char, 8192> buf{};

        for (;;)
        {
            std::size_t used = 0;
            boost::system::error_code ec;

            // 读取响应头
            while (true)
            {
                const auto sv = std::string_view(buf.data(), used);
                if (sv.find("\r\n\r\n") != std::string_view::npos)
                {
                    break;
                }

                auto n = co_await socket.async_read_some(
                    net::buffer(buf.data() + used, buf.size() - used),
                    net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    if (ec == net::error::eof && config_.debug_output)
                    {
                        psm::trace::debug("stress mode: server closed connection");
                    }
                    HandleDisconnect(socket, is_connected);
                    co_return;
                }
                used += n;
            }

            // 解析 Content-Length
            std::size_t body_size = 0;
            {
                const auto raw = std::string_view(buf.data(), used);
                auto pos = raw.find("Content-Length:");
                if (pos != std::string_view::npos)
                {
                    auto val_start = pos + 15;
                    while (val_start < raw.size() && raw[val_start] == ' ')
                        ++val_start;
                    auto val_end = raw.find("\r\n", val_start);
                    auto len_str = raw.substr(val_start, val_end == std::string_view::npos ? std::string_view::npos : val_end - val_start);
                    for (char c : len_str)
                    {
                        if (c >= '0' && c <= '9')
                        {
                            body_size = body_size * 10 + (c - '0');
                        }
                    }
                }
            }

            stats_.total_requests.fetch_add(1, std::memory_order_relaxed);
            stats_.success_requests.fetch_add(1, std::memory_order_relaxed);
            stats_.bytes_received.fetch_add(body_size, std::memory_order_relaxed);

            auto request_end = std::chrono::steady_clock::now();
            auto latency_ms = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(request_end - request_start).count());
            UpdateLatencyStats(latency_ms);
            request_start = request_end;

            if (config_.debug_output)
            {
                static std::atomic<int> debug_counter{0};
                if (debug_counter.fetch_add(1, std::memory_order_relaxed) % 100 == 0)
                {
                    psm::trace::debug("[调试] stress响应: body={} bytes", body_size);
                }
            }

            memory::string ack_data("ACK", mr);
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await net::async_write(socket, net::buffer(ack_data), token);
            if (ec)
            {
                HandleDisconnect(socket, is_connected);
                co_return;
            }

            if (stats_.total_requests.load(std::memory_order_relaxed) >= config_.total_requests)
            {
                HandleDisconnect(socket, is_connected);
                co_return;
            }
        }
    }

    /**
     * @brief 处理普通模式
     * @details 读取单个 HTTP 响应并更新统计。
     * @param socket TCP 套接字
     * @param is_connected 连接状态标志
     * @param mr 内存资源
     * @param request_start 请求开始时间
     */
    net::awaitable<void> HandleNormalMode(tcp::socket &socket, bool &is_connected,
                                          memory::resource_pointer mr, std::chrono::steady_clock::time_point request_start)
    {
        // 读取 HTTP 响应头
        std::array<char, 8192> buf{};
        std::size_t used = 0;
        boost::system::error_code ec;

        while (true)
        {
            const auto sv = std::string_view(buf.data(), used);
            if (sv.find("\r\n\r\n") != std::string_view::npos)
            {
                break;
            }

            auto n = co_await socket.async_read_some(
                net::buffer(buf.data() + used, buf.size() - used),
                net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                psm::trace::error("[错误] 读取响应失败");
                HandleError(socket, is_connected, ec);
                co_return;
            }
            used += n;
        }

        auto request_end = std::chrono::steady_clock::now();
        auto latency_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(request_end - request_start).count());

        // 解析状态行: HTTP/1.1 200 OK
        const auto raw = std::string_view(buf.data(), used);
        const auto line_end = raw.find("\r\n");
        const auto first_space = raw.find(' ');
        const auto second_space = (line_end != std::string_view::npos && first_space != std::string_view::npos)
                                      ? raw.find(' ', first_space + 1)
                                      : std::string_view::npos;

        int status_code = 0;
        if (first_space != std::string_view::npos && second_space != std::string_view::npos && second_space < line_end)
        {
            const auto status_str = raw.substr(first_space + 1, second_space - first_space - 1);
            for (char c : status_str)
            {
                if (c >= '0' && c <= '9')
                {
                    status_code = status_code * 10 + (c - '0');
                }
            }
        }

        // 解析 Content-Length 和 Connection
        std::size_t body_size = 0;
        bool keep_alive = false;
        {
            const auto headers_end = raw.find("\r\n\r\n");
            if (headers_end != std::string_view::npos)
            {
                auto headers = raw.substr(0, headers_end);
                auto pos = headers.find("Content-Length:");
                if (pos != std::string_view::npos)
                {
                    auto val_start = pos + 15;
                    while (val_start < headers.size() && headers[val_start] == ' ')
                        ++val_start;
                    auto val_end = headers.find("\r\n", val_start);
                    auto len_str = headers.substr(val_start, val_end == std::string_view::npos ? std::string_view::npos : val_end - val_start);
                    for (char c : len_str)
                    {
                        if (c >= '0' && c <= '9')
                        {
                            body_size = body_size * 10 + (c - '0');
                        }
                    }
                }
                // 简单检查 Connection 头
                pos = headers.find("Connection:");
                if (pos != std::string_view::npos)
                {
                    auto val_start = pos + 11;
                    while (val_start < headers.size() && headers[val_start] == ' ')
                        ++val_start;
                    if (headers.substr(val_start).starts_with("keep-alive"))
                    {
                        keep_alive = true;
                    }
                }
            }
        }

        if (config_.debug_output)
        {
            static std::atomic<int> debug_counter{0};
            if (debug_counter.fetch_add(1, std::memory_order_relaxed) % 100 == 0)
            {
                psm::trace::debug("[调试] 响应状态: {}, body大小: {} bytes, 延迟: {} ms",
                                  status_code, body_size, latency_ms);
            }
        }

        stats_.total_requests.fetch_add(1, std::memory_order_relaxed);
        if (status_code == 200)
        {
            stats_.success_requests.fetch_add(1, std::memory_order_relaxed);
            stats_.bytes_received.fetch_add(body_size, std::memory_order_relaxed);
            UpdateLatencyStats(latency_ms);
        }
        else
        {
            stats_.failed_requests.fetch_add(1, std::memory_order_relaxed);
            stats_.protocol_errors.fetch_add(1, std::memory_order_relaxed);
        }

        if (!keep_alive)
        {
            HandleDisconnect(socket, is_connected);
        }
    }

    /**
     * @brief 更新延迟统计
     * @param latency_ms 本次延迟（毫秒）
     */
    void UpdateLatencyStats(std::uint64_t latency_ms)
    {
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

    /**
     * @brief 处理错误
     * @param socket TCP 套接字
     * @param is_connected 连接状态标志
     * @param ec 错误码
     * @details 根据错误类型更新统计信息并断开连接。
     */
    void HandleError(tcp::socket &socket, bool &is_connected, const boost::system::error_code &ec)
    {
        stats_.failed_requests.fetch_add(1, std::memory_order_relaxed);

        if (ec == net::error::timed_out ||
            ec.message().find("timeout") != std::string::npos)
        {
            stats_.timeout_errors.fetch_add(1, std::memory_order_relaxed);
        }
        else if (ec == net::error::connection_reset ||
                 ec == net::error::connection_aborted ||
                 ec == net::error::broken_pipe ||
                 ec == net::error::not_connected ||
                 ec == net::error::eof)
        {
            stats_.connection_errors.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            stats_.protocol_errors.fetch_add(1, std::memory_order_relaxed);
        }

        HandleDisconnect(socket, is_connected);
    }

    /**
     * @brief 断开连接
     * @param socket TCP 套接字
     * @param is_connected 连接状态标志
     * @details 关闭套接字并更新活跃连接数。
     */
    void HandleDisconnect(tcp::socket &socket, bool &is_connected)
    {
        if (is_connected)
        {
            boost::system::error_code ec;
            socket.shutdown(tcp::socket::shutdown_both, ec);
            socket.close(ec);
            active_connections.fetch_sub(1, std::memory_order_relaxed);
            is_connected = false;
        }
    }

    /**
     * @brief 异步休眠
     * @param duration 休眠时长
     * @return 协程任务
     */
    static net::awaitable<void> AsyncSleep(std::chrono::milliseconds duration)
    {
        net::steady_timer timer(co_await net::this_coro::executor);
        timer.expires_after(duration);
        co_await timer.async_wait(net::use_awaitable);
    }
};

/**
 * @brief 程序入口
 * @return 退出码
 */
int main()
{
    SetConsoleOutputCP(CP_UTF8);

    psm::trace::config trace_config;
    trace_config.enable_console = true;
    trace_config.enable_file = false;
    trace_config.log_level = "debug";
    psm::trace::init(trace_config);

    try
    {
        stress_config config;
        client client(config);
        client.start();
    }
    catch (const std::exception &e)
    {
        psm::trace::error("发生异常: {}", e.what());
    }

    psm::trace::shutdown();

    return 0;
}
