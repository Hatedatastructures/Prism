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
    co_await msg.console_write_line(deprecated_log::level::debug, "这是一条 `debug` 级别的消息");
    co_await msg.console_write_line(deprecated_log::level::info, "这是一条 `info` 级别的消息");
    co_await msg.console_write_line(deprecated_log::level::warn, "这是一条 `warn` 级别的消息");
    co_await msg.console_write_line(deprecated_log::level::error, "这是一条 `error` 级别的消息");
    co_await msg.console_write_line(deprecated_log::level::fatal, "这是一条 `fatal` 级别的消息");
    co_return;
}

/**
 * @brief 测试格式化日志输出
 * @param msg 日志实例
 * @return `asio::awaitable<void>`
 */
asio::awaitable<void> test_formatted_logs(const deprecated_log::coroutine_log &msg)
{
    int age = 25;
    std::string name = "张三";
    double score = 95.5;

    co_await msg.console_write_fmt(deprecated_log::level::info,
                                   "用户信息: 姓名=`{}`, 年龄=`{}`, 分数=`{:.2f}`\n", name, age, score);

    co_await msg.console_write_fmt(deprecated_log::level::warn,
                                   "测试多个参数: `{}`, `{}`, `{}`, `{}`\n", 1, "字符串", 3.14, true);

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
    co_await msg.file_write_line(test_file, "这是一条写入文件的测试日志");
    co_await msg.file_write_line(test_file, "这是第二条文件日志，测试追加功能");

    co_await msg.console_write_line(deprecated_log::level::info, "文件日志已写入到 `" + test_dir + "/" + test_file + "`");
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
                                       "来自协程 `{}` 的并发日志, 计数: `{}`\n", id, i);
        // 模拟一些异步操作
        asio::steady_timer timer(co_await asio::this_coro::executor);
        timer.expires_after(std::chrono::milliseconds(10));
        co_await timer.async_wait(asio::use_awaitable);
    }
    co_return;
}

/**
 * @brief 异步主函数
 * @param msg 日志实例
 * @return `asio::awaitable<void>`
 */
asio::awaitable<void> async_main(deprecated_log::coroutine_log &msg)
{
    try
    {
        co_await msg.console_write_line(deprecated_log::level::info, "=== 开始控制台级别测试 ===");
        co_await test_console_levels(msg);

        co_await msg.console_write_line(deprecated_log::level::info, "=== 开始格式化日志测试 ===");
        co_await test_formatted_logs(msg);

        co_await msg.console_write_line(deprecated_log::level::info, "=== 开始文件日志测试 ===");
        co_await test_file_logging(msg);

        co_await msg.console_write_line(deprecated_log::level::info, "=== 开始并发日志测试 ===");
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

        co_await msg.console_write_line(deprecated_log::level::info, "=== 所有测试完成 ===");
        co_await msg.shutdown();
    }
    catch (const std::exception &e)
    {
        std::cerr << "测试过程中发生异常: " << e.what() << std::endl;
    }
    co_return;
}

int main()
{
    std::cout << "日志模块综合测试程序启动..." << std::endl;

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
                std::cerr << "事件循环异常: " << e.what() << std::endl;
            }
        };
        std::jthread io_thread(event_loop);

        std::cout << "主线程等待测试完成..." << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "主程序发生异常: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
