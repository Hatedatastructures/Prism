/**
 * @file test_runner.hpp
 * @brief 轻量级测试运行框架
 * @details 提供统一的测试计数、断言和结果汇总机制，
 * 供所有单元测试复用，消除重复的 passed/failed 计数器和日志函数。
 * 无外部依赖，仅依赖 prism::trace 进行日志输出。
 */

#pragma once

#include <prism/trace/spdlog.hpp>

#include <format>
#include <string_view>

namespace psm::testing
{
    /**
     * @brief 轻量级测试运行器
     * @details 管理测试通过/失败计数器，提供统一的日志输出和结果汇总。
     * 每个测试可执行文件创建一个实例，通过 tag 参数区分不同测试模块的日志来源。
     */
    class test_runner
    {
    public:
        /**
         * @brief 构造测试运行器
         * @param tag 日志标签，用于区分不同测试模块（如 "Session", "Crypto" 等）
         */
        explicit test_runner(const std::string_view tag) noexcept
            : tag_(tag)
        {
        }

        /** @brief 获取通过计数 */
        [[nodiscard]] auto passed_count() const noexcept -> int
        {
            return passed_;
        }

        /** @brief 获取失败计数 */
        [[nodiscard]] auto failed_count() const noexcept -> int
        {
            return failed_;
        }

        /**
         * @brief 输出信息级别日志
         * @param msg 日志消息
         */
        auto log_info(const std::string_view msg) const -> void
        {
            psm::trace::info("[{}] {}", tag_, msg);
        }

        /**
         * @brief 记录测试通过并递增计数器
         * @param msg 测试名称
         */
        auto log_pass(const std::string_view msg) -> void
        {
            ++passed_;
            psm::trace::info("[{}] PASS: {}", tag_, msg);
        }

        /**
         * @brief 记录测试失败并递增计数器
         * @param msg 失败原因
         */
        auto log_fail(const std::string_view msg) -> void
        {
            ++failed_;
            psm::trace::error("[{}] FAIL: {}", tag_, msg);
        }

        /**
         * @brief 检查条件，通过时记录 pass，失败时记录 fail
         * @param condition 待检查的条件
         * @param message 条件描述
         */
        auto check(const bool condition, const std::string_view message) -> void
        {
            if (condition)
            {
                log_pass(message);
            }
            else
            {
                log_fail(message);
            }
        }

        /**
         * @brief 输出测试结果汇总并返回退出码
         * @details 打印通过/失败计数，关闭日志系统。
         * @return 0 表示全部通过，1 表示存在失败
         */
        [[nodiscard]] auto summary() -> int
        {
            psm::trace::info("[{}] Results: {} passed, {} failed", tag_, passed_, failed_);
            psm::trace::shutdown();
            return failed_ > 0 ? 1 : 0;
        }

    private:
        std::string_view tag_;
        int passed_ = 0;
        int failed_ = 0;
    };
} // namespace psm::testing
