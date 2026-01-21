#include <trace/monitor.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <filesystem>
#include <trace/spdlog.hpp>

namespace deprecated_log = ngx::trace::deprecated;
namespace asio = boost::asio;
namespace fs = std::filesystem;
/**
 * @brief 测试不同级别的控制台日志输出
 * @param msg 日志实例
 * @return `asio::awaitable<void>`
 */
asio::awaitable<void> test_console_levels(const deprecated_log::coroutine_log &msg)
{
    co_await msg.console_write_line(deprecated_log::level::debug, "This is a `debug` level message");
    co_await msg.console_write_line(deprecated_log::level::info, "This is an `info` level message");
    co_await msg.console_write_line(deprecated_log::level::warn, "This is a `warn` level message");
    co_await msg.console_write_line(deprecated_log::level::error, "This is an `error` level message");
    co_await msg.console_write_line(deprecated_log::level::fatal, "This is a `fatal` level message");
    co_return;
}

/**
 * @brief 测试格式化日志输
 * @param msg 日志实例
 * @return `asio::awaitable<void>`
 */
asio::awaitable<void> test_formatted_logs(const deprecated_log::coroutine_log &msg)
{
    int age = 25;
    std::string name = "Zhang San";
    double score = 95.5;

    co_await msg.console_write_fmt(deprecated_log::level::info,
                                   "User Info: Name=`{}`, Age=`{}`, Score=`{:.2f}`\n", name, age, score);

    co_await msg.console_write_fmt(deprecated_log::level::warn,
                                   "Test multiple args: `{}`, `{}`, `{}`, `{}`\n", 1, "String", 3.14, true);

    co_return;
}

/**
 * @brief 测试文件日志输出
 * @param msg 日志实例
 * @return `asio::awaitable<void>`
 */
asio::awaitable<void> test_file_logging(deprecated_log::coroutine_log &msg)
{
    std::string test_dir = "test_logs";
    std::string test_file = "test.trace";

    // 设置输出目录
    co_await msg.set_output_directory(test_dir);

    // 写入文件日志
    co_await msg.file_write_line(test_file, "This is a test log written to file");
    co_await msg.file_write_line(test_file, "This is the second log, testing append");

    co_await msg.console_write_line(deprecated_log::level::info, "File log written to `" + test_dir + "/" + test_file + "`");
    co_return;
}

/**
 * @brief 测试并发日志输出
 * @param msg 日志实例
 * @param id 协程标识 ID
 * @return `asio::awaitable<void>`
 */
asio::awaitable<void> test_concurrent_logging(const deprecated_log::coroutine_log &msg, int id)
{
    for (int i = 0; i < 5; ++i)
    {
        co_await msg.console_write_fmt(deprecated_log::level::info,
                                       "Concurrent log from coroutine `{}` count: `{}`\n", id, i);
        // 模拟一些异步操作，增加并发测试的真实性
        asio::steady_timer timer(co_await asio::this_coro::executor);
        timer.expires_after(std::chrono::milliseconds(10));
        co_await timer.async_wait(asio::use_awaitable);
    }
    co_return;
}

/**
 * @brief 异步主函数，协调所有测试任务
 * @param msg 日志实例
 * @return `asio::awaitable<void>`
 */
asio::awaitable<void> async_main(deprecated_log::coroutine_log &msg)
{
    try
    {
        co_await msg.console_write_line(deprecated_log::level::info, "=== Start Console Level Test ===");
        co_await test_console_levels(msg);

        co_await msg.console_write_line(deprecated_log::level::info, "=== Start Formatted Log Test ===");
        co_await test_formatted_logs(msg);

        co_await msg.console_write_line(deprecated_log::level::info, "=== Start File Log Test ===");
        co_await test_file_logging(msg);

        co_await msg.console_write_line(deprecated_log::level::info, "=== Start Concurrent Log Test ===");
        std::vector<asio::awaitable<void>> tasks;
        for (int i = 0; i < 20; ++i)
        {
            asio::co_spawn(co_await asio::this_coro::executor, test_concurrent_logging(msg, i),
                           asio::detached);
        }

        // 等待一段时间以确保并发任务完成
        asio::steady_timer timer(co_await asio::this_coro::executor);
        timer.expires_after(std::chrono::seconds(1));
        co_await timer.async_wait(asio::use_awaitable);

        co_await msg.console_write_line(deprecated_log::level::info, "=== All Tests Completed ===");
        co_await msg.shutdown();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception during test: " << e.what() << std::endl;
    }
    co_return;
}

int main()
{
    std::cout << "Log module comprehensive test started..." << std::endl;

    try
    {
        asio::io_context io_context;

        // 创建日志实例
        deprecated_log::coroutine_log msg(io_context.get_executor());

        // 启动主测试协程
        asio::co_spawn(io_context, async_main(msg), asio::detached);

        // 在子线程中运行事件循环
        auto event_loop = [&io_context]()
        {
            try
            {
                io_context.run();
            }
            catch (const std::exception &e)
            {
                std::cerr << "Event loop exception: " << e.what() << std::endl;
            }
        };
        std::jthread io_thread(event_loop);

        std::cout << "Main thread waiting for test completion..." << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Main program exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

