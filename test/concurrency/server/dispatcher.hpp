/**
 * @file dispatcher.hpp
 * @brief HTTP 分发器模块
 * @details 基于 Boost.Asio 和 C++20 协程的多端口监听分发器，负责接受连接并创建对应的会话。
 *
 * 核心特性：
 * - 多端口监听：支持主端口和统计端口（可扩展）
 * - 协程优先：使用 `net::co_spawn` 启动监听协程
 * - 零互斥锁：无锁设计，依赖线程封闭 (Thread Confinement)
 * - 内存池绑定：每个连接关联独立的会话内存池
 * - 优雅关闭：支持优雅关闭所有监听器和连接
 *
 * @note 设计原则：
 * - 单一职责：仅负责端口监听和连接分发
 * - 依赖注入：通过构造函数注入路由器、处理器、统计信息等依赖
 * - 资源绑定：监听器生命周期与 `io_context` 绑定
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>
#include <memory>
#include <string_view>

#include "routing.hpp"
#include "handler.hpp"
#include "statistics.hpp"
#include "socket.hpp"
#include "session.hpp"

#include <boost/asio.hpp>

#include <forward-engine/trace.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>

namespace srv::core
{
    namespace net = boost::asio;

    using namespace srv::routing;
    using namespace srv::handler;
    using namespace srv::statistics;
    using namespace srv::socket;
    using namespace srv::session;

    /**
     * @struct dispatcher_config
     * @brief 分发器配置结构
     */
    struct dispatcher_config
    {
        std::uint16_t main_port = 6789;                                   ///< 主业务端口
        std::uint16_t stats_port = 9876;                                  ///< 统计信息端口
        std::uint32_t thread_count = std::thread::hardware_concurrency(); ///< IO 线程数
        std::string static_root = "webroot";                              ///< 静态文件根目录
    };

    /**
     * @class http_dispatcher
     * @brief HTTP 分发器类
     * @details 管理多个端口的监听，为每个接受的连接创建对应的会话。
     */
    class http_dispatcher final
    {
    public:
        /**
         * @brief 构造函数
         * @param io_context 异步 IO 上下文
         * @param config 分发器配置
         */
        explicit http_dispatcher(net::io_context &io_context, const dispatcher_config &config)
            : io_context_(io_context),
              config_(config),
              main_router_{},
              stats_router_{},
              stats_{},
              file_handler_{config.static_root + "/main"},
              stats_file_handler_{config.static_root + "/stats"},
              work_guard_(net::make_work_guard(io_context))
        {
        }

        /**
         * @brief 启动分发器
         * @details 启动所有端口的监听协程，并初始化工作线程池。
         */
        void start()
        {
            // 启动监听协程
            net::co_spawn(io_context_, listen_main_port(), net::detached);
            net::co_spawn(io_context_, listen_stats_port(), net::detached);

            // 启动 IO 线程池
            start_worker_threads();

            ngx::trace::info("分发器已启动: 主端口={}, 统计端口={}, 线程数={}",
                             config_.main_port, config_.stats_port, config_.thread_count);
        }

        /**
         * @brief 停止分发器
         * @details 优雅停止所有监听器，等待现有连接处理完成。
         */
        void stop()
        {
            ngx::trace::info("正在停止分发器...");

            work_guard_.reset();
            io_context_.stop();

            for (auto &thread : worker_threads_)
            {
                if (thread.joinable())
                {
                    thread.join();
                }
            }

            worker_threads_.clear();
            ngx::trace::info("分发器已停止");
        }

        /**
         * @brief 获取 IO 上下文引用
         */
        [[nodiscard]] net::io_context &get_io_context() noexcept
        {
            return io_context_;
        }

        /**
         * @brief 获取统计信息引用
         */
        [[nodiscard]] detailed_stats &get_stats() noexcept
        {
            return stats_;
        }

    private:
        /**
         * @brief 启动工作线程池
         */
        void start_worker_threads()
        {
            worker_threads_.reserve(config_.thread_count);

            for (std::uint32_t i = 0; i < config_.thread_count; ++i)
            {
                auto worker_func = [this, i]()
                {
                    worker_thread_entry(i);
                };
                worker_threads_.emplace_back(worker_func);
            }
        }

        /**
         * @brief 工作线程入口函数
         */
        void worker_thread_entry([[maybe_unused]] std::uint32_t thread_id)
        {
            try
            {
                io_context_.run();
            }
            catch (const std::exception &e)
            {
                ngx::trace::error("IO线程异常: {}", e.what());
            }
        }

        /**
         * @brief 监听主端口协程
         */
        net::awaitable<void> listen_main_port()
        {
            auto executor = co_await net::this_coro::executor;
            net::ip::tcp::acceptor acceptor(executor,
                                            net::ip::tcp::endpoint(net::ip::tcp::v4(), config_.main_port));

            ngx::trace::debug("主端口监听器已启动: {}", config_.main_port);

            while (true)
            {
                boost::system::error_code ec;
                auto socket = co_await acceptor.async_accept(net::redirect_error(net::use_awaitable, ec));

                if (ec)
                {
                    if (ec == net::error::operation_aborted)
                    {
                        ngx::trace::debug("主端口监听器被中止");
                        break;
                    }
                    ngx::trace::warn("主端口接受连接错误: {}", ec.message());
                    continue;
                }

                const auto conn_index = stats_.add_connection_info(connection_info{});
                tcp_wrapper tcp_stream(std::move(socket));

                // 创建主会话（使用 main_router）
                main_session session(std::move(tcp_stream), stats_, file_handler_, main_router_, conn_index);
                net::co_spawn(executor, session.start(), net::detached);
            }
        }

        /**
         * @brief 监听统计端口协程
         */
        net::awaitable<void> listen_stats_port()
        {
            auto executor = co_await net::this_coro::executor;
            net::ip::tcp::acceptor acceptor(executor,
                                            net::ip::tcp::endpoint(net::ip::tcp::v4(), config_.stats_port));

            ngx::trace::debug("统计端口监听器已启动: {}", config_.stats_port);

            while (true)
            {
                boost::system::error_code ec;
                auto socket = co_await acceptor.async_accept(net::redirect_error(net::use_awaitable, ec));

                if (ec)
                {
                    if (ec == net::error::operation_aborted)
                    {
                        ngx::trace::debug("统计端口监听器被中止");
                        break;
                    }
                    ngx::trace::warn("统计端口接受连接错误: {}", ec.message());
                    continue;
                }

                const auto conn_index = stats_.add_connection_info(connection_info{});
                tcp_wrapper tcp_stream(std::move(socket));

                // 创建统计会话（使用 stats_router）
                stats_session session(std::move(tcp_stream), stats_, stats_file_handler_, stats_router_, conn_index);
                net::co_spawn(executor, session.start(), net::detached);
            }
        }

    private:
        net::io_context &io_context_;
        dispatcher_config config_;
        main_router main_router_;
        stats_router stats_router_;
        detailed_stats stats_;
        static_handler file_handler_;
        static_handler stats_file_handler_;
        std::vector<std::jthread> worker_threads_;
        net::executor_work_guard<net::io_context::executor_type> work_guard_;
    };

    /**
     * @brief 设置信号处理器（跨平台）
     * @param io_context IO 上下文
     * @param stop_token 停止标志原子变量
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
     * @brief 加载分发器配置（从 JSON 文件）
     */
    [[nodiscard]] inline dispatcher_config load_config_from_json(std::string_view config_path)
    {
        // 简化的配置加载，实际项目中可使用 glaze 等库
        dispatcher_config config;

        // 这里暂时返回默认配置，实际应读取 JSON 文件
        ngx::trace::info("使用默认分发器配置");
        return config;
    }

    /**
     * @brief 服务器主入口函数
     * @param argc 命令行参数个数
     * @param argv 命令行参数数组
     * @return 程序退出码
     */
    inline int handler(int argc, char *argv[])
    {
        dispatcher_config config;

        // 简单的命令行参数解析
        for (int i = 1; i < argc; ++i)
        {
            std::string_view arg = argv[i];
            if (arg == "--help" || arg == "-h")
            {
                std::cout << "用法: " << argv[0] << " [选项]" << std::endl;
                std::cout << "选项:" << std::endl;
                std::cout << "  --config FILE    配置文件路径 (默认: server.json)" << std::endl;
                std::cout << "  --main-port PORT 主端口 (默认: 6789)" << std::endl;
                std::cout << "  --stats-port PORT 统计端口 (默认: 9876)" << std::endl;
                std::cout << "  --threads N      IO 线程数 (默认: CPU核心数)" << std::endl;
                std::cout << "  --help, -h       显示帮助信息" << std::endl;
                return 0;
            }
            else if (arg == "--config" && i + 1 < argc)
            {
                config = load_config_from_json(argv[++i]);
            }
            else if (arg == "--main-port" && i + 1 < argc)
            {
                config.main_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
            }
            else if (arg == "--stats-port" && i + 1 < argc)
            {
                config.stats_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
            }
            else if (arg == "--threads" && i + 1 < argc)
            {
                config.thread_count = static_cast<std::uint32_t>(std::stoi(argv[++i]));
            }
        }

        // 创建 IO 上下文
        net::io_context io_context;

        // 创建分发器
        http_dispatcher dispatcher(io_context, config);

        // 设置信号处理
        std::atomic<bool> stop_token{false};
        setup_signal_handlers(io_context, stop_token);

        // 启动分发器
        dispatcher.start();

        // 信号处理线程
        std::jthread signal_thread([&]()
                                   {
            while (!stop_token.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            dispatcher.stop(); });

        // 主线程等待分发器停止
        signal_thread.join();

        return 0;
    }
}