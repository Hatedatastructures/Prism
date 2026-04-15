/**
 * @file Trace.cpp
 * @brief 日志系统测试
 * @details 测试 psm::trace (spdlog 封装) 的初始化、五级日志输出、关闭和日志文件验证。
 */

#include <prism/trace/spdlog.hpp>
#include <prism/memory.hpp>

#include "common/test_runner.hpp"

#include <exception>
#include <filesystem>
#include <format>
#include <string_view>

namespace fs = std::filesystem;

namespace
{
    psm::testing::test_runner runner("Trace");

    /**
     * @brief 获取文件大小，失败时返回 0
     * @param path 文件路径
     * @return 文件大小（字节），路径无效或出错时返回 0
     */
    [[nodiscard]] auto file_size_or_zero(const fs::path &path) -> std::uintmax_t
    {
        std::error_code ec;
        const auto size = fs::file_size(path, ec);
        return ec ? 0 : size;
    }
} // namespace

/**
 * @brief 测试日志系统初始化、输出和关闭
 */
void TestTraceInitAndWrite()
{
    runner.log_info("=== TestTraceInitAndWrite ===");

    // 使用独立的测试日志目录，避免污染主日志
    const fs::path path_name = fs::path("test_logs") / "trace";
    const std::string file_name = "trace_test.log";

    // 构造测试专用日志配置
    psm::trace::config cfg;
    cfg.path_name = path_name.string();
    cfg.file_name = file_name;
    cfg.max_size = 1024U * 1024U;
    cfg.max_files = 2U;
    cfg.queue_size = 8192U;
    cfg.thread_count = 1U;
    cfg.enable_console = true;
    cfg.log_level = "debug";
    cfg.trace_name = "trace_test";

    psm::trace::init(cfg);

    // 依次输出五个日志级别，验证完整日志链路
    psm::trace::debug("trace_test: debug `{}`", 1);
    psm::trace::info("trace_test: info `{}`", 2);
    psm::trace::warn("trace_test: warn `{}`", 3);
    psm::trace::error("trace_test: error `{}`", 4);
    psm::trace::fatal("trace_test: fatal `{}`", 5);

    // 必须关闭才能确保异步日志刷盘到磁盘
    psm::trace::shutdown();

    // 重新初始化为默认配置，供后续测试输出使用
    psm::trace::init({});

    // 检查日志文件是否已生成且非空
    const fs::path log_path = path_name / file_name;
    const auto size = file_size_or_zero(log_path);
    if (size == 0)
    {
        runner.log_fail(std::format("log file missing or empty: {}", log_path.string()));
        return;
    }

    runner.log_pass("TraceInitAndWrite");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行日志初始化与五级输出测试；
 * 测试过程中先关闭日志以确保刷盘，随后读文件校验日志内容非空，最后重新初始化供结果输出。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化 PMR 全局内存池
    psm::memory::system::enable_global_pooling();
    // 使用默认配置初始化日志系统
    psm::trace::init({});

    runner.log_info("Starting trace tests...");

    TestTraceInitAndWrite();

    runner.log_info("Trace tests completed.");

    // 测试结束前关闭日志，确保所有消息刷盘
    return runner.summary();
}
