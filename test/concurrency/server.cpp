/**
 * @file server.cpp
 * @brief HTTP 测试服务器主入口
 * @details 基于 Boost.Asio 和 C++20 协程的高性能 HTTP 测试服务器。
 *          实现基于 CPU 核心数的线程池、优雅停机和信号处理。
 *
 * 核心特性：
 * - 多线程协程：基于 CPU 核心数的 io_context 线程池
 * - 优雅停机：安全处理 SIGINT/SIGTERM，拒绝直接 kill
 * - 内存安全：零拷贝架构，内存池绑定每个连接
 * - 高性能：无锁设计，线程封闭 (Thread Confinement)
 *
 * @note 设计原则：
 * - 配置驱动：支持命令行参数和配置文件
 * - 资源管理：RAII 管理所有资源
 * - 异常安全：所有异常被捕获并记录，避免崩溃
 */

#include "server/dispatcher.hpp"
#ifdef _WIN32
#include <windows.h>
#endif

#include <forward-engine/trace.hpp>
#include <iostream>
#include <atomic>
#include <csignal>
#include <thread>
#include <vector>
#include <filesystem>

/**
 * @brief 全局停止标志（用于信号处理）
 */
static std::atomic<bool> g_stop_requested{false};

/**
 * @brief 信号处理函数（Unix/Linux）
 */
#ifdef _WIN32
static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_CLOSE_EVENT)
    {
        g_stop_requested.store(true);
        return TRUE;
    }
    return FALSE;
}
#else
static void signal_handler(int signal)
{
    if (signal == SIGINT || signal == SIGTERM)
    {
        g_stop_requested.store(true);
    }
}
#endif

/**
 * @brief 设置跨平台信号处理
 */
static void setup_signal_handlers()
{
#ifdef _WIN32
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#else
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    // 忽略 SIGPIPE（避免因连接断开而崩溃）
    signal(SIGPIPE, SIG_IGN);
#endif
}

/**
 * @brief 解析命令行参数
 * @param argc 参数个数
 * @param argv 参数数组
 * @return 分发器配置
 */
static srv::core::dispatcher_config parse_command_line(int argc, char *argv[])
{
    srv::core::dispatcher_config config;

    for (int i = 1; i < argc; ++i)
    {
        std::string_view arg = argv[i];
        if (arg == "--help" || arg == "-h")
        {
            std::cout << "用法: " << argv[0] << " [选项]" << std::endl;
            std::cout << "选项:" << std::endl;
            std::cout << "  --main-port PORT   主端口 (默认: 6789)" << std::endl;
            std::cout << "  --stats-port PORT  统计端口 (默认: 9876)" << std::endl;
            std::cout << "  --threads N        IO 线程数 (默认: CPU核心数)" << std::endl;
            std::cout << "  --static-root DIR  静态文件根目录 (默认: webroot)" << std::endl;
            std::cout << "  --help, -h         显示帮助信息" << std::endl;
            std::exit(0);
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
        else if (arg == "--static-root" && i + 1 < argc)
        {
            config.static_root = argv[++i];
        }
    }

    // 将静态根目录转换为绝对路径，确保服务器从任何目录运行都能找到文件
    namespace fs = std::filesystem;
    try
    {
        fs::path root_path(config.static_root);
        if (root_path.is_relative())
        {
            // 转换为相对于当前工作目录的绝对路径
            root_path = fs::absolute(root_path);
            config.static_root = root_path.string();
        }
        
        // 检查路径是否存在
        if (!fs::exists(root_path))
        {
            std::cerr << "警告: 静态文件根目录不存在: " << config.static_root << std::endl;
        }
        else if (!fs::is_directory(root_path))
        {
            std::cerr << "警告: 静态文件根目录不是目录: " << config.static_root << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "警告: 无法解析静态文件根目录路径 '" << config.static_root 
                  << "': " << e.what() << std::endl;
    }

    return config;
}

/**
 * @brief 主函数
 * @param argc 命令行参数个数
 * @param argv 命令行参数数组
 * @return 程序退出码
 */
int main(const int argc, char *argv[])
{
    // Windows 控制台 UTF-8 支持
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    // 初始化日志系统
    ngx::trace::config log_config;
    log_config.enable_console = true;
    log_config.enable_file = false;
    log_config.thread_count = 2;
    log_config.log_level = "info";
    ngx::trace::init(log_config);

    ngx::trace::info("ForwardEngine HTTP 测试服务器启动中...");

    try
    {
        // 解析命令行参数
        const auto config = parse_command_line(argc, argv);
        ngx::trace::info("配置: 主端口={}, 统计端口={}, 线程数={}, 静态根目录={}",
                         config.main_port, config.stats_port, config.thread_count, config.static_root);

        // 创建 IO 上下文
        boost::asio::io_context io_context;

        // 创建分发器
        srv::core::http_dispatcher dispatcher(io_context, config);

        // 设置信号处理
        setup_signal_handlers();
        ngx::trace::info("信号处理器已设置 (Ctrl+C 或 SIGINT/SIGTERM 触发优雅停机)");

        // 启动分发器（启动监听协程）
        dispatcher.start();
        ngx::trace::info("分发器已启动，监听主端口 {} 和统计端口 {}", config.main_port, config.stats_port);

        // 创建并运行 IO 线程池
        std::vector<std::jthread> io_threads;
        io_threads.reserve(config.thread_count);

        ngx::trace::info("启动 {} 个 IO 线程...", config.thread_count);
        for (std::uint32_t i = 0; i < config.thread_count; ++i)
        {
            io_threads.emplace_back([&io_context, i]()
                                    {
                try
                {
                    ngx::trace::debug("IO 线程 {} 启动", i);
                    io_context.run();
                    ngx::trace::debug("IO 线程 {} 退出", i);
                }
                catch (const std::exception &e)
                {
                    ngx::trace::error("IO 线程 {} 异常: {}", i, e.what());
                } });
        }

        // 等待停止信号
        ngx::trace::info("服务器已启动，等待停止信号 (Ctrl+C 或 SIGINT/SIGTERM)...");
        while (!g_stop_requested.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // 优雅停机
        ngx::trace::info("收到停止信号，开始优雅停机...");
        
        // 停止 IO 上下文
        io_context.stop();
        
        // 停止分发器
        dispatcher.stop();

        // 等待所有 IO 线程结束
        for (auto &thread : io_threads)
        {
            if (thread.joinable())
            {
                thread.join();
            }
        }

        ngx::trace::info("服务器已安全停止");
    }
    catch (const std::exception &e)
    {
        ngx::trace::error("服务器启动失败: {}", e.what());
        return 1;
    }

    return 0;
}