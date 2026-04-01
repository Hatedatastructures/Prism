#include <trace/spdlog.hpp>
#include <prism/exception/network.hpp>
#include <prism/fault/code.hpp>
#include <boost/asio.hpp>
#include <exception>
#include <filesystem>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string>

namespace net = boost::asio;
namespace fs = std::filesystem;
namespace ntrace = psm::trace;

namespace
{
    [[nodiscard]] std::uintmax_t file_size_or_zero(const fs::path &path)
    {
        std::error_code ec;
        const auto size = fs::file_size(path, ec);
        if (ec)
        {
            return 0;
        }
        return size;
    }
}

/**
 * @brief `spdlog` 封装的最小回归测试
 * @details
 * - 验证 `trace::init` 能创建目录并初始化异步 logger。
 * - 验证 `co_await trace::info/warn/error` 能成功调用且不会阻塞。
 * - 验证 `trace::shutdown` 能刷盘并释放资源。
 * @param executor `asio` 执行器
 * @return `net::awaitable<void>`
 * @note 该函数不会主动运行，需要由现有测试用例显式 `co_await` 调用。
 */
net::awaitable<void> run_spdlog_test(const net::any_io_executor executor)
{
    const fs::path path_name = fs::path("test_logs") / "spdlog";
    const std::string file_name = "spdlog_test.log";

    ntrace::config cfg;
    cfg.path_name = path_name.string();
    cfg.file_name = file_name;
    cfg.max_size = 1024U * 1024U;
    cfg.max_files = 2U;
    cfg.queue_size = 8192U;
    cfg.thread_count = 1U;
    cfg.enable_console = true;
    cfg.log_level = "debug";
    cfg.trace_name = "spdlog_test";

    ntrace::init(cfg);

    ntrace::debug("spdlog_test: debug `{}`", 1);
    ntrace::info("spdlog_test: info `{}`", 2);
    ntrace::warn("spdlog_test: warn `{}`", 3);
    ntrace::error("spdlog_test: error `{}`", 4);
    ntrace::fatal("spdlog_test: fatal `{}`", 5);

    ntrace::shutdown();

    const fs::path log_path = path_name / file_name;
    const auto size = file_size_or_zero(log_path);
    if (size == 0)
    {
        throw psm::exception::network("spdlog_test: 日志文件未生成或为空: " + log_path.string());
    }

    (void)executor;
    co_return;
}

int main()
{
    try
    {
        net::io_context ioc;
        std::exception_ptr test_error;

        auto completion = [&ioc, &test_error](const std::exception_ptr &ep)
        {
            test_error = ep;
            ioc.stop();
        };

        net::co_spawn(ioc, run_spdlog_test(ioc.get_executor()), completion);
        ioc.run();

        if (test_error)
        {
            std::rethrow_exception(test_error);
        }
    }
    catch (const std::exception &e)
    { 
        std::cerr << std::format("spdlog_test failed: {}", e.what()) << std::endl;
        return 1;
    }

    std::cout << "spdlog_test passed" << std::endl;
    return 0;
}
