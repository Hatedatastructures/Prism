/**
 * @file dual_port.hpp
 * @brief 双端口服务器定义
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
 */
#pragma once

#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <atomic>
#include <cstdio>
#include <fstream>
#include <filesystem>

#include "../router/main_router.hpp"
#include "../router/stats_router.hpp"
#include "../handler/static_file.hpp"
#include "../stats/metrics.hpp"
#include "../stream/tcp_wrapper.hpp"
#include "../stream/ssl_wrapper.hpp"
#include "../session.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>

namespace srv::core
{
    namespace fs = std::filesystem;
    using namespace srv::router;
    using namespace srv::handler;
    using namespace srv::stats;
    using namespace srv::stream;
    using namespace srv::session;

    class dual_port_server final
    {
    public:
        explicit dual_port_server(std::uint16_t main_port = 6789, std::uint16_t stats_port = 9876,
                                  std::uint32_t threads = std::thread::hardware_concurrency(),
                                  bool enable_ssl = false, std::string_view cert_file = "",
                                  std::string_view key_file = "")
            : main_port_(main_port), stats_port_(stats_port), thread_count_(threads),
              enable_ssl_(enable_ssl), cert_file_(cert_file), key_file_(key_file),
              work_guard_(boost::asio::make_work_guard(io_context_))
        {
        }

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

                create_static_file_handlers();

                return true;
            }
            catch (const std::exception &e)
            {
                std::fprintf(stderr, "初始化失败: %s\n", e.what());
                return false;
            }
        }

        void run()
        {
            io_threads_.reserve(thread_count_);

            for (std::uint32_t i = 0; i < thread_count_; ++i)
            {
                io_threads_.emplace_back([this, i]()
                                         { this->io_worker_thread(i); });
            }

            boost::asio::co_spawn(io_context_, listen_main_port(), boost::asio::detached);
            boost::asio::co_spawn(io_context_, listen_stats_port(), boost::asio::detached);

            std::printf("服务器已启动\n");
            std::printf("主端口: %d (HTTP%s)\n", main_port_, enable_ssl_ ? "S" : "");
            std::printf("统计端口: %d (HTTP)\n", stats_port_);
            std::printf("IO线程数: %u\n", thread_count_);

            io_context_.run();
        }

        void stop()
        {
            std::printf("正在停止服务器...\n");

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
            std::printf("服务器已停止\n");
        }

        [[nodiscard]] boost::asio::io_context &get_io_context() noexcept
        {
            return io_context_;
        }

        [[nodiscard]] detailed_stats &get_stats() noexcept
        {
            return stats_;
        }

    private:
        void io_worker_thread(std::uint32_t thread_id)
        {
            try
            {
                io_context_.run();
            }
            catch (const std::exception &e)
            {
                std::fprintf(stderr, "IO线程 %u 异常: %s\n", thread_id, e.what());
            }
        }

        boost::asio::awaitable<void> listen_main_port()
        {
            auto executor = co_await boost::asio::this_coro::executor;
            boost::asio::ip::tcp::acceptor acceptor(executor, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), main_port_));

            std::printf("主端口监听器已启动: %d\n", main_port_);

            while (true)
            {
                boost::beast::error_code ec;
                auto socket = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                if (ec)
                {
                    if (ec == boost::asio::error::operation_aborted)
                    {
                        break;
                    }
                    continue;
                }

                const auto conn_index = stats_.add_connection_info(connection_info{});

                if (enable_ssl_ && ssl_context_)
                {
                    ssl_stream_wrapper ssl_stream(std::move(socket), *ssl_context_);
                    boost::asio::co_spawn(executor, do_main_session(std::move(ssl_stream), stats_, static_file_handler{}, main_router_, conn_index), boost::asio::detached);
                }
                else
                {
                    tcp_stream_wrapper tcp_stream(std::move(socket));
                    boost::asio::co_spawn(executor, do_main_session(std::move(tcp_stream), stats_, static_file_handler{}, main_router_, conn_index), boost::asio::detached);
                }
            }
        }

        boost::asio::awaitable<void> listen_stats_port()
        {
            auto executor = co_await boost::asio::this_coro::executor;
            boost::asio::ip::tcp::acceptor acceptor(executor, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), stats_port_));

            std::printf("统计端口监听器已启动: %d\n", stats_port_);

            while (true)
            {
                boost::beast::error_code ec;
                auto socket = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                if (ec)
                {
                    if (ec == boost::asio::error::operation_aborted)
                    {
                        break;
                    }
                    continue;
                }

                const auto conn_index = stats_.add_connection_info(connection_info{});

                tcp_stream_wrapper tcp_stream(std::move(socket));
                boost::asio::co_spawn(executor, do_stats_session(std::move(tcp_stream), stats_, static_file_handler{}, stats_router_, conn_index), boost::asio::detached);
            }
        }

        void route_request(ngx::protocol::http::request &req, ngx::protocol::http::response &resp)
        {
            try
            {
                handle_static_file(req, resp);
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.body(std::string_view(R"({"error":"Internal Server Error"})"));
                stats_.increment_errors();
            }
        }

        void handle_static_file(ngx::protocol::http::request &req, ngx::protocol::http::response &resp)
        {
            const std::string target = std::string(req.target());

            std::string file_path;
            if (target.starts_with("/api/"))
            {
                file_path = "webroot/main" + target;
            }
            else
            {
                file_path = "webroot/main" + target;
            }

            try
            {
                std::ifstream file(file_path, std::ios::binary);
                if (!file)
                {
                    resp.status(ngx::protocol::http::status::not_found);
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    const std::string error_msg = R"({"error":"Not Found","path":")" + file_path + R"("})";
                    resp.body(std::string_view(error_msg));
                    stats_.increment_not_found();
                    return;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                resp.status(ngx::protocol::http::status::ok);

                if (file_path.ends_with(".html"))
                {
                    resp.set(ngx::protocol::http::field::content_type, "text/html; charset=utf-8");
                }
                else if (file_path.ends_with(".css"))
                {
                    resp.set(ngx::protocol::http::field::content_type, "text/css; charset=utf-8");
                }
                else if (file_path.ends_with(".js"))
                {
                    resp.set(ngx::protocol::http::field::content_type, "application/javascript; charset=utf-8");
                }
                else if (file_path.ends_with(".json"))
                {
                    resp.set(ngx::protocol::http::field::content_type, "application/json; charset=utf-8");
                }
                else if (file_path.ends_with(".png"))
                {
                    resp.set(ngx::protocol::http::field::content_type, "image/png");
                }
                else if (file_path.ends_with(".jpg") || file_path.ends_with(".jpeg"))
                {
                    resp.set(ngx::protocol::http::field::content_type, "image/jpeg");
                }
                else if (file_path.ends_with(".svg"))
                {
                    resp.set(ngx::protocol::http::field::content_type, "image/svg+xml");
                }

                resp.body(std::move(content));
                stats_.increment_static_files();
            }
            catch (const std::exception &e)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                const std::string error_msg = R"({"error":"Internal Server Error","message":")" + std::string(e.what()) + R"("})";
                resp.body(std::string_view(error_msg));
                stats_.increment_errors();
            }
        }

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
                std::fprintf(stderr, "创建SSL上下文失败: %s\n", e.what());
                return nullptr;
            }
        }

        void create_static_file_handlers()
        {
            try
            {
                fs::create_directories("webroot/main");
                fs::create_directories("webroot/stats");
                std::printf("静态文件目录已创建: webroot/main, webroot/stats\n");
            }
            catch (const std::exception &e)
            {
                std::fprintf(stderr, "创建静态文件目录失败: %s\n", e.what());
            }
        }

        std::uint16_t main_port_;
        std::uint16_t stats_port_;
        std::uint32_t thread_count_;
        bool enable_ssl_;
        std::string cert_file_;
        std::string key_file_;
        boost::asio::io_context io_context_;
        std::vector<std::thread> io_threads_;
        std::shared_ptr<boost::asio::ssl::context> ssl_context_;
        main_router main_router_;
        stats_router stats_router_;
        detailed_stats stats_;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    };

    inline void setup_signal_handlers([[maybe_unused]] boost::asio::io_context &io_context, [[maybe_unused]] std::atomic<bool> &stop_token)
    {
#ifdef _WIN32
        (void)io_context;
        (void)stop_token;
        SetConsoleCtrlHandler(
            [](DWORD dwCtrlType) -> BOOL WINAPI
            {
                if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT)
                {
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

    inline int main_handler(int argc, char *argv[])
    {
        std::uint16_t main_port = 6789;
        std::uint16_t stats_port = 9876;
        std::uint32_t threads = std::thread::hardware_concurrency();
        bool enable_ssl = false;
        std::string cert_file;
        std::string key_file;

        for (int i = 1; i < argc; ++i)
        {
            std::string_view arg = argv[i];
            if (arg == "--help" || arg == "-h")
            {
                std::printf("用法: %s [选项]\n", argv[0]);
                std::printf("选项:\n");
                std::printf("  --main-port PORT       主端口 (默认: 6789)\n");
                std::printf("  --stats-port PORT      统计端口 (默认: 9876)\n");
                std::printf("  --threads NUM          IO线程数 (默认: CPU核心数)\n");
                std::printf("  --enable-ssl           启用SSL\n");
                std::printf("  --cert-file FILE       SSL证书文件\n");
                std::printf("  --key-file FILE        SSL私钥文件\n");
                std::printf("  --help, -h             显示帮助信息\n");
                return 0;
            }
            else if (arg == "--main-port" && i + 1 < argc)
            {
                main_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
            }
            else if (arg == "--stats-port" && i + 1 < argc)
            {
                stats_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
            }
            else if (arg == "--threads" && i + 1 < argc)
            {
                threads = static_cast<std::uint32_t>(std::stoi(argv[++i]));
            }
            else if (arg == "--enable-ssl")
            {
                enable_ssl = true;
            }
            else if (arg == "--cert-file" && i + 1 < argc)
            {
                cert_file = argv[++i];
            }
            else if (arg == "--key-file" && i + 1 < argc)
            {
                key_file = argv[++i];
            }
        }

        if (enable_ssl && (cert_file.empty() || key_file.empty()))
        {
            std::fprintf(stderr, "错误: 启用SSL时必须指定证书文件和私钥文件\n");
            return 1;
        }

        dual_port_server server(main_port, stats_port, threads, enable_ssl, cert_file, key_file);

        if (!server.initialize())
        {
            std::fprintf(stderr, "服务器初始化失败\n");
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

        server.run();

        if (signal_thread.joinable())
        {
            signal_thread.join();
        }

        return 0;
    }
}
