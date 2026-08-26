/**
 * @file TestRunner.hpp
 * @brief 轻量级测试运行框架
 * @details 提供统一的测试计数、断言和结果汇总机制，
 * 供所有单元测试复用，消除重复的 passed/failed 计数器和日志函数。
 * 无外部依赖，仅依赖 prism::trace 进行日志输出。
 */

#pragma once

#include <prism/diagnose/log.hpp>

#include <format>
#include <string_view>

namespace Preview::Testing
{
    /**
     * @brief 轻量级测试运行器
     * @details 管理测试通过/失败计数器，提供统一的日志输出和结果汇总。
     * 每个测试可执行文件创建一个实例，通过 tag 参数区分不同测试模块的日志来源。
     */
    class TestRunner
    {
    public:
        /**
         * @brief 构造测试运行器
         * @param tag 日志标签，用于区分不同测试模块（如 "Session", "Crypto" 等）
         */
        explicit TestRunner(std::string_view tag) noexcept : Tag_(tag)
        {
        }

        /** @brief 获取通过计数 */
        [[nodiscard]] auto PassedCount() const noexcept -> int
        {
            return Passed_;
        }

        /** @brief 获取失败计数 */
        [[nodiscard]] auto FailedCount() const noexcept -> int
        {
            return Failed_;
        }

        /**
         * @brief 输出信息级别日志
         * @param msg 日志消息
         */
        void LogInfo(std::string_view msg) const
        {
            psm::diagnose::info("[{}] {}", Tag_, msg);
        }

        /**
         * @brief 记录测试通过并递增计数器
         * @param msg 测试名称
         */
        void LogPass(std::string_view msg)
        {
            ++Passed_;
            psm::diagnose::info("[{}] PASS: {}", Tag_, msg);
        }

        /**
         * @brief 记录测试失败并递增计数器
         * @param msg 失败原因
         */
        void LogFail(std::string_view msg)
        {
            ++Failed_;
            psm::diagnose::error("[{}] FAIL: {}", Tag_, msg);
        }

        /**
         * @brief 检查条件，通过时记录 pass，失败时记录 fail
         * @param condition 待检查的条件
         * @param message 条件描述
         */
        void Check(const bool condition, std::string_view message)
        {
            if (condition)
            {
                LogPass(message);
            }
            else
            {
                LogFail(message);
            }
        }

        /**
         * @brief 输出测试结果汇总并返回退出码
         * @details 打印通过/失败计数，关闭日志系统。
         * @return 0 表示全部通过，1 表示存在失败
         */
        [[nodiscard]] auto Summary() -> int
        {
            psm::diagnose::info("[{}] Results: {} passed, {} failed", Tag_, Passed_, Failed_);
            psm::diagnose::shutdown();
            if (Failed_ > 0)
            {
                return 1;
            }
            return 0;
        }

    private:
        std::string_view Tag_;
        int Passed_ = 0;
        int Failed_ = 0;
    };
} // namespace Preview::Testing
