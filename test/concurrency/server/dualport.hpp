/**
 * @file dualport.hpp
 * @brief 双端口服务器模块
 * @details 基于 beast::tcp_stream，提供高性能双端口 HTTP 服务器。
 *
 * 核心特性：
 * - 双端口监听：主端口提供业务 API，统计端口提供统计信息
 * - 多线程 IO：支持多线程 IO 处理
 * - 优雅关闭：支持优雅关闭所有连接
 *
 * @note 设计原则：
 * - 协程优先：所有异步操作使用 co_await
 * - 零互斥锁：无锁设计
 */

#pragma once

#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <atomic>
#include <iostream>
#include <fstream>
#include <filesystem>

#include "routing.hpp"
#include "processor.hpp"
#include "statistics.hpp"
#include "socket.hpp"
#include "connection.hpp"

#include <boost/asio.hpp>

#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/transformer/json.hpp>
#include <forward-engine/trace.hpp>

namespace srv::core
{
    namespace fs = std::filesystem;
    namespace net = boost::asio;

    using namespace srv::routing;
    using namespace srv::processor;
    using namespace srv::statistics;
    using namespace srv::socket;
    using namespace srv::connection;
    using namespace ngx::transformer::json;

    /**
     * @struct server_config
     * @brief 服务器配置结构
     */
    struct server_config
    {
        std::uint16_t main_port = 6789;
        std::uint16_t stats_port = 9876;
        std::uint32_t threads = std::thread::hardware_concurrency();
    };

    /**
     * @brief 从 JSON 文件加载服务器配置
     */
    [[nodiscard]] inline server_config load_config_from_json(const std::string_view config_path)
    {
        server_config config;

        std::ifstream file(std::string(config_path), std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "警告: 无法打开配置文件 " << config_path << "，使用默认配置" << std::endl;
            return config;
        }

        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        if (content.empty())
        {
            std::cerr << "警告: 配置文件为空，使用默认配置" << std::endl;
            return config;
        }

        if (!ngx::transformer::json::deserialize(std::string_view(content), config))
        {
            std::cerr << "错误: 配置文件解析失败，使用默认配置" << std::endl;
            return server_config{};
        }

        std::cout << "配置文件加载成功: " << config_path << std::endl;
        return config;
    }

    /**
     * @class dualport
     * @brief 双端口服务器类
     */
    class dualport final
    {
    public:
        explicit dualport(std::uint16_t main_port = 6789, std::uint16_t stats_port = 9876,
                          std::uint32_t threads = std::thread::hardware_concurrency())
            : server_port_(main_port), stats_port_(stats_port), thread_count_(threads),
              work_guard_(net::make_work_guard(io_context_))
        {
        }

        [[nodiscard]] bool initialize()
        {
            try
            {
                create_directories();
                return true;
            }
            catch (const std::exception &e)
            {
                std::cerr << "初始化失败: " << e.what() << std::endl;
                return false;
            }
        }

        void run()
        {
            io_threads_.reserve(thread_count_);

            for (std::uint32_t i = 0; i < thread_count_; ++i)
            {
                auto worker_function = [this, i]()
                {
                    this->worker_thread(i);
                };
                io_threads_.emplace_back(worker_function);
            }

            net::co_spawn(io_context_, start_http_server(), net::detached);
            net::co_spawn(io_context_, start_dashboard_server(), net::detached);

            std::cout << "服务器已启动" << std::endl;
            std::cout << "主端口: " << server_port_ << " (HTTP)" << std::endl;
            std::cout << "统计端口: " << stats_port_ << " (HTTP)" << std::endl;
            std::cout << "IO线程数: " << thread_count_ << std::endl;

            // 主线程等待所有工作线程完成
            for (auto &thread : io_threads_)
            {
                if (thread.joinable())
                {
                    thread.join();
                }
            }
        }

        void stop()
        {
            std::cout << "正在停止服务器..." << std::endl;

            work_guard_.reset();
            io_context_.stop();

            for (auto &thread : io_threads_)
            {
                if (thread.joinable())
                {
                    thread.join();
                }
            }

            io_threads_.clear();
            std::cout << "服务器已停止" << std::endl;
        }

        [[nodiscard]] net::io_context &get_io_context() noexcept
        {
            return io_context_;
        }

        [[nodiscard]] detailed_stats &get_stats() noexcept
        {
            return stats_;
        }

    private:
        void worker_thread([[maybe_unused]] std::uint32_t thread_id)
        {
            try
            {
                io_context_.run();
            }
            catch (const std::exception &e)
            {
                std::cerr << "IO线程异常: " << e.what() << std::endl;
            }
        }

        net::awaitable<void> start_http_server()
        {
            auto executor = co_await net::this_coro::executor;
            net::ip::tcp::acceptor acceptor(executor, net::ip::tcp::endpoint(net::ip::tcp::v4(), server_port_));

            std::cout << "主端口监听器已启动: " << server_port_ << std::endl;
            ngx::trace::debug("start http server");

            while (true)
            {
                boost::system::error_code ec;
                auto socket = co_await acceptor.async_accept(net::redirect_error(net::use_awaitable, ec));

                if (ec)
                {
                    if (ec == net::error::operation_aborted)
                    {
                        ngx::trace::debug("http server accept operation aborted");
                        break;
                    }
                    continue;
                }

                const auto conn_index = stats_.add_connection_info(connection_info{});
                tcp_wrapper tcp_stream(std::move(socket));
                net::co_spawn(executor, do_main(std::move(tcp_stream), stats_, static_handler{"webroot/main"}, main_router_, conn_index), net::detached);
            }
        }

        net::awaitable<void> start_dashboard_server()
        {
            auto executor = co_await net::this_coro::executor;
            net::ip::tcp::acceptor acceptor(executor, net::ip::tcp::endpoint(net::ip::tcp::v4(), stats_port_));

            std::cout << "仪表盘监听器已启动: " << stats_port_ << std::endl;
            ngx::trace::debug("start dashboard server");

            while (true)
            {
                boost::system::error_code ec;
                auto socket = co_await acceptor.async_accept(net::redirect_error(net::use_awaitable, ec));

                if (ec)
                {
                    if (ec == net::error::operation_aborted)
                    {
                        ngx::trace::debug("dashboard server accept operation aborted");
                        break;
                    }
                    continue;
                }

                const auto conn_index = stats_.add_connection_info(connection_info{});
                tcp_wrapper tcp_stream(std::move(socket));
                net::co_spawn(executor, do_dashboard(std::move(tcp_stream), stats_, static_handler{"webroot/stats"}, stats_router_, conn_index), net::detached);
            }
        }

        void create_directories()
        {
            try
            {
                fs::create_directories("webroot/main");
                fs::create_directories("webroot/stats");
                std::cout << "静态文件目录已创建: webroot/main, webroot/stats" << std::endl;
            }
            catch (const std::exception &e)
            {
                std::cerr << "创建静态文件目录失败: " << e.what() << std::endl;
            }
        }

        std::uint16_t server_port_;
        std::uint16_t stats_port_;
        std::uint32_t thread_count_;
        net::io_context io_context_;
        std::vector<std::jthread> io_threads_;
        main_router main_router_;
        stats_router stats_router_;
        detailed_stats stats_;
        net::executor_work_guard<net::io_context::executor_type> work_guard_;
    };

    /**
     * @brief 设置信号处理器
     */
    inline void setup_signal_handlers([[maybe_unused]] net::io_context &io_context, std::atomic<bool> &stop_token)
    {
#ifdef _WIN32
        static std::atomic<bool> *global_stop_token = nullptr;
        global_stop_token = &stop_token;

        SetConsoleCtrlHandler(
            [](DWORD dwCtrlType) -> BOOL WINAPI
            {
                if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT)
                {
                    if (global_stop_token != nullptr)
                    {
                        global_stop_token->store(true);
                    }
                    return TRUE;
                }
                return FALSE;
            },
            TRUE);
#else
        net::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait(
            [&stop_token](const boost::system::error_code &, int)
            {
                stop_token.store(true);
            });
#endif
    }

    /**
     * @brief 主入口函数
     */
    inline int handler(int argc, char *argv[])
    {
        // 默认从当前目录读取配置文件
        std::string config_path = "server.json";

        for (int i = 1; i < argc; ++i)
        {
            std::string_view arg = argv[i];
            if (arg == "--help" || arg == "-h")
            {
                std::cout << "用法: " << argv[0] << " [选项]" << std::endl;
                std::cout << "选项:" << std::endl;
                std::cout << "  --config FILE    配置文件路径 (默认: server.json)" << std::endl;
                std::cout << "  --help, -h       显示帮助信息" << std::endl;
                return 0;
            }
            else if (arg == "--config" && i + 1 < argc)
            {
                config_path = argv[++i];
            }
        }

        const auto config = load_config_from_json(config_path);

        ngx::trace::debug("创建 server 对象");
        dualport server(config.main_port, config.stats_port, config.threads);

        if (!server.initialize())
        {
            std::cerr << "服务器初始化失败" << std::endl;
            return 1;
        }

        std::atomic<bool> stop_token{false};
        setup_signal_handlers(server.get_io_context(), stop_token);

        std::jthread signal_thread([&]()
                                   {
                                       while (!stop_token.load())
                                       {
                                           std::this_thread::sleep_for(std::chrono::milliseconds(100));
                                       }
                                       server.stop(); });

        ngx::trace::debug("启动 server 对象");
        server.run();

        return 0;
    }
}

namespace glz
{
    template <>
    struct meta<srv::core::server_config>
    {
        using T = srv::core::server_config;
        static constexpr auto value = glz::object(
            "main_port", &T::main_port,
            "stats_port", &T::stats_port,
            "threads", &T::threads);
    };
}
