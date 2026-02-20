/**
 * @file dualport.hpp
 * @brief 双端口服务器模块
 * @details 管理双端口 HTTP/HTTPS 服务器，支持多核 IO 并发和优雅关闭。
 *
 * 核心特性：
 * - 双端口监听：主端口提供业务 API，统计端口提供统计信息
 * - 多线程 IO：支持多线程 IO 处理
 * - SSL/TLS 支持：可选的 SSL/TLS 加密
 * - 优雅关闭：支持优雅关闭所有连接
 *
 * @note 设计原则：
 * - RAII 管理：自动管理资源生命周期
 * - 协程风格：使用 Boost.Asio 协程处理异步操作
 * - 线程安全：使用原子操作保证线程安全
 *
 * @see httpsession.hpp
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
#include "httpsession.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/transformer/json.hpp>

namespace srv::core
{
    namespace fs = std::filesystem;
    using namespace srv::routing;
    using namespace srv::processor;
    using namespace srv::statistics;
    using namespace srv::socket;
    using namespace srv::httpsession;
    using namespace ngx::transformer::json;

    /**
     * @struct server_config
     * @brief 服务器配置结构
     * @details 定义双端口服务器的所有配置项，支持从 `JSON` 文件加载。
     *
     * 字段说明：
     * @details - `main_port`：主端口号，提供业务 `API`，默认 `6789`；
     * @details - `stats_port`：统计端口号，提供统计信息，默认 `9876`；
     * @details - `threads`：`IO` 线程数，默认为 `CPU` 核心数；
     * @details - `enable_ssl`：是否启用 `SSL/TLS`，默认 `false`；
     * @details - `cert_file`：`SSL` 证书文件路径（`PEM` 格式）；
     * @details - `key_file`：`SSL` 私钥文件路径（`PEM` 格式）。
     *
     * @note 配置结构使用 `ngx::transformer::json` 模块进行 `JSON` 反序列化。
     * @warning 启用 `SSL` 时必须同时提供 `cert_file` 和 `key_file`。
     */
    struct server_config
    {
        std::uint16_t main_port = 6789;
        std::uint16_t stats_port = 9876;
        std::uint32_t threads = std::thread::hardware_concurrency();
        bool enable_ssl = false;
        std::string cert_file;
        std::string key_file;
    };

    /**
     * @brief 从 `JSON` 文件加载服务器配置
     * @param config_path 配置文件路径
     * @return 加载的配置结构，失败时返回默认配置
     * @details 读取指定路径的 `JSON` 文件并解析为 `server_config` 结构。
     * 使用 `ngx::transformer::json::deserialize` 进行反序列化。
     *
     * @note 如果文件不存在或解析失败，返回默认配置。
     * @warning 配置文件必须是有效的 `JSON` 格式。
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
     * @details 管理双端口 HTTP/HTTPS 服务器，支持多核 IO 并发和优雅关闭
     */
    class dualport final
    {
    public:
        /**
         * @brief 构造函数
         * @param main_port 主端口
         * @param stats_port 统计端口
         * @param threads IO 线程数
         * @param enable_ssl 是否启用 SSL
         * @param cert_file SSL 证书文件路径
         * @param key_file SSL 私钥文件路径
         */
        explicit dualport(std::uint16_t main_port = 6789, std::uint16_t stats_port = 9876,
                          std::uint32_t threads = std::thread::hardware_concurrency(),
                          bool enable_ssl = false, std::string_view cert_file = "",
                          std::string_view key_file = "")
            : server_port_(main_port), stats_port_(stats_port), thread_count_(threads),
              enable_ssl_(enable_ssl), cert_file_(cert_file), key_file_(key_file),
              work_guard_(boost::asio::make_work_guard(io_context_))
        {
        }

        /**
         * @brief 初始化服务器
         * @return 是否成功
         */
        [[nodiscard]] bool initialize()
        {
            try
            {
                if (enable_ssl_)
                {
                    ssl_context_ = create_ssl_context();
                    if (!ssl_context_)
                    {
                        return false;
                    }
                }

                create_directories();

                return true;
            }
            catch (const std::exception &e)
            {
                std::cerr << "初始化失败: " << e.what() << std::endl;
                return false;
            }
        }

        /**
         * @brief 运行服务器
         */
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

            boost::asio::co_spawn(io_context_, start_http_server(), boost::asio::detached);
            boost::asio::co_spawn(io_context_, start_dashboard_server(), boost::asio::detached);

            std::cout << "服务器已启动" << std::endl;
            std::cout << "主端口: " << server_port_ << " (HTTP" << (enable_ssl_ ? "S" : "") << ")" << std::endl;
            std::cout << "统计端口: " << stats_port_ << " (HTTP)" << std::endl;
            std::cout << "IO线程数: " << thread_count_ << std::endl;

            io_context_.run();
        }

        /**
         * @brief 停止服务器
         */
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

        /**
         * @brief 获取 IO 上下文
         * @return IO 上下文引用
         */
        [[nodiscard]] boost::asio::io_context &get_io_context() noexcept
        {
            return io_context_;
        }

        /**
         * @brief 获取统计数据
         * @return 统计数据引用
         */
        [[nodiscard]] detailed_stats &get_stats() noexcept
        {
            return stats_;
        }

    private:
        /**
         * @brief 工作线程函数
         * @param thread_id 线程标识符
         * @details 运行 IO 上下文的事件循环，处理异步操作
         */
        void worker_thread(std::uint32_t thread_id)
        {
            try
            {
                io_context_.run();
            }
            catch (const std::exception &e)
            {
                std::cerr << "IO线程 " << thread_id << " 异常: " << e.what() << std::endl;
            }
        }

        /**
         * @brief 启动 HTTP 服务器协程
         * @return 协程任务
         * @details 接受主端口的连接请求，并根据配置创建 TCP 或 SSL 会话
         */
        boost::asio::awaitable<void> start_http_server()
        {
            auto executor = co_await boost::asio::this_coro::executor;
            boost::asio::ip::tcp::acceptor acceptor(executor, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), server_port_));

            std::cout << "主端口监听器已启动: " << server_port_ << std::endl;

            ngx::trace::debug("start http server");

            while (true)
            {
                boost::beast::error_code ec;
                auto socket = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                if (ec)
                {
                    if (ec == boost::asio::error::operation_aborted)
                    {
                        ngx::trace::debug("http server accept operation aborted");
                        break;
                    }
                    continue;
                }

                const auto conn_index = stats_.add_connection_info(connection_info{});

                if (enable_ssl_ && ssl_context_)
                {
                    ssl_wrapper ssl_stream(std::move(socket), *ssl_context_);
                    boost::asio::co_spawn(executor, do_main_session(std::move(ssl_stream), stats_, static_handler{}, main_router_, conn_index), boost::asio::detached);
                }
                else
                {
                    tcp_wrapper tcp_stream(std::move(socket));
                    boost::asio::co_spawn(executor, do_main_session(std::move(tcp_stream), stats_, static_handler{}, main_router_, conn_index), boost::asio::detached);
                }
            }
        }

        /**
         * @brief 监听统计端口协程
         * @return 协程任务
         * @details 接受统计端口的连接请求，创建 TCP 会话处理统计 API 请求
         */
        boost::asio::awaitable<void> start_dashboard_server()
        {
            auto executor = co_await boost::asio::this_coro::executor;
            boost::asio::ip::tcp::acceptor acceptor(executor, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), stats_port_));

            std::cout << "仪表盘监听器已启动: " << stats_port_ << std::endl;

            ngx::trace::debug("start dashboard server");
            while (true)
            {
                boost::beast::error_code ec;
                auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
                auto socket = co_await acceptor.async_accept(token);

                if (ec)
                {
                    if (ec == boost::asio::error::operation_aborted)
                    { // 操作中止
                        ngx::trace::debug("dashboard server accept operation aborted");
                        break;
                    }
                    continue;
                }

                const auto conn_index = stats_.add_connection_info(connection_info{});

                tcp_wrapper tcp_stream(std::move(socket));
                boost::asio::co_spawn(executor, do_dashboard_session(std::move(tcp_stream), stats_, static_handler{}, stats_router_, conn_index), boost::asio::detached);
            }
        }

        /**
         * @brief 创建 SSL 上下文
         * @return SSL 上下文共享指针，失败时返回 nullptr
         * @details 配置 TLS 1.3 并加载证书和私钥
         */
        [[nodiscard]] std::shared_ptr<boost::asio::ssl::context> create_ssl_context()
        {
            try
            {
                auto ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv13);
                ctx->set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3 |
                                 boost::asio::ssl::context::single_dh_use);
                ctx->use_certificate_chain_file(std::string(cert_file_));
                ctx->use_private_key_file(std::string(key_file_), boost::asio::ssl::context::pem);
                return ctx;
            }
            catch (const std::exception &e)
            {
                std::cerr << "创建SSL上下文失败: " << e.what() << std::endl;
                return nullptr;
            }
        }

        /**
         * @brief 创建静态文件目录
         * @details 创建 webroot/main 和 webroot/stats 目录用于存放静态文件
         */
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

        /// @brief web服务端口号
        std::uint16_t server_port_;
        /// @brief 统计端口号
        std::uint16_t stats_port_;
        /// @brief IO 线程数
        std::uint32_t thread_count_;
        /// @brief 是否启用 SSL
        bool enable_ssl_;
        /// @brief SSL 证书文件路径
        std::string cert_file_;
        /// @brief SSL 私钥文件路径
        std::string key_file_;
        /// @brief IO 上下文
        boost::asio::io_context io_context_;
        /// @brief IO 线程列表
        std::vector<std::thread> io_threads_;
        /// @brief SSL 上下文
        std::shared_ptr<boost::asio::ssl::context> ssl_context_;
        /// @brief 主端口路由器
        main_router main_router_;
        /// @brief 统计端口路由器
        stats_router stats_router_;
        /// @brief 服务器统计数据
        detailed_stats stats_;
        /// @brief 工作守卫，防止 IO 上下文提前退出
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    };

    /**
     * @brief 设置信号处理器
     * @param io_context IO 上下文
     * @param stop_token 停止标志
     * @note Windows 下使用 SetConsoleCtrlHandler，Linux 下使用 signal_set
     */
    inline void setup_signal_handlers([[maybe_unused]] boost::asio::io_context &io_context, std::atomic<bool> &stop_token)
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
        boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait(
            [&stop_token](const boost::beast::error_code &, int)
            {
                stop_token.store(true);
            });
#endif
    }

    /**
     * @brief 主入口函数
     * @param argc 参数个数
     * @param argv 参数数组
     * @return 退出码
     * @details 从 `JSON` 配置文件加载服务器配置，支持 `--config` 参数指定配置文件路径。
     *
     * 配置文件格式 (`JSON`)：
     * ```
     * {
     *     "main_port": 6789,
     *     "stats_port": 9876,
     *     "threads": 8,
     *     "enable_ssl": false,
     *     "cert_file": "",
     *     "key_file": ""
     * }
     * ```
     *
     * @note 默认配置文件路径为 `server.json`。
     * @note 如果配置文件不存在，使用默认配置启动服务器。
     */
    inline int handler(int argc, char *argv[])
    {
        std::string config_path = R"(C:\Users\C1373\Desktop\code\ForwardEngine\test\concurrency\server.json)";

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
            else
            {
                ngx::trace::debug("未知参数: {}", arg);
            }
        }

        const auto config = load_config_from_json(config_path);

        if (config.enable_ssl && (config.cert_file.empty() || config.key_file.empty()))
        {
            std::cerr << "错误: 启用SSL时必须指定证书文件和私钥文件" << std::endl;
            return 1;
        }

        ngx::trace::debug("创建 server 对象");
        dualport server(config.main_port, config.stats_port, config.threads, config.enable_ssl, config.cert_file, config.key_file);

        if (!server.initialize())
        {
            std::cerr << "服务器初始化失败" << std::endl;
            return 1;
        }

        std::atomic<bool> stop_token{false};
        setup_signal_handlers(server.get_io_context(), stop_token);

        auto signal_function = [&]()
        {
            while (!stop_token.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            server.stop();
        };

        std::jthread signal_thread(signal_function);

        ngx::trace::debug("启动 server 对象");
        server.run();

        if (signal_thread.joinable())
        {
            signal_thread.join();
        }

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
            "threads", &T::threads,
            "enable_ssl", &T::enable_ssl,
            "cert_file", &T::cert_file,
            "key_file", &T::key_file);
    };
}
