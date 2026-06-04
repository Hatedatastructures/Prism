/**
 * @file spdlog.hpp
 * @brief 日志接口封装
 * @details 封装 spdlog 库，提供统一的日志记录接口，
 * 支持多级别日志输出和编译期字段管道选择。
 *
 * 默认字段选择（使用 level_default 链）：
 *   trace::debug("msg")
 *
 * 自定义字段选择（pipe 语法）：
 *   trace::debug<field::sid | field::protocol>("msg")
 *
 * 所有接口内部捕获异常，确保日志失败不影响业务逻辑。
 * @note 允许重复调用 init，后一次覆盖前一次。
 * @warning 必须在程序退出前调用 shutdown 释放线程池资源。
 */
#pragma once

#include <prism/trace/config.hpp>
#include <prism/trace/context.hpp>

#include <spdlog/fmt/fmt.h>
#include <spdlog/mdc.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <string>
#include <string_view>
#include <utility>


namespace psm::trace
{

    /**
     * @brief 设置 MDC 键值对
     * @param key MDC 键
     * @param value MDC 值
     * @details 将键值对存入当前线程的 MDC 上下文，后续日志输出
     * 时自动携带该上下文信息。线程安全，每个线程维护独立副本。
     * @note 由于异步日志模式下日志消息被投递到后台线程池格式化，
     * MDC 内容在格式化阶段已由后台线程读取，因此需要配合
     * 自定义 formatter 将 MDC 上下文嵌入消息载荷。
     */
    void mdc_set(const std::string &key, const std::string &value);

    /**
     * @brief 删除 MDC 键
     * @param key 要删除的 MDC 键
     * @details 从当前线程的 MDC 上下文中移除指定键值对。
     */
    void mdc_remove(const std::string &key);

    /**
     * @brief 清空所有 MDC 键值对
     * @details 移除当前线程 MDC 上下文中的所有键值对。
     */
    void mdc_clear();

    /**
     * @brief 构建当前线程 MDC 上下文的前缀字符串
     * @return 格式化后的 MDC 前缀，如 "[session_id=abc][request_id=123] "
     * @details 遍历当前线程的 MDC 映射，生成 "[key=value]" 格式的
     * 前缀字符串。MDC 为空时返回空字符串。该函数供日志模板函数
     * 内部调用，将 MDC 上下文嵌入消息载荷，绕过异步日志模式下
     * thread_local 在后台线程池中不可见的问题。
     */
    [[nodiscard]] auto build_mdc_prefix() -> std::string;

    /**
     * @brief 初始化全局日志器
     * @param cfg 日志配置对象
     * @details 根据配置创建异步日志器，支持文件和控制台
     * 双输出。如果已存在日志器，会先销毁旧的再创建新的。
     */
    void init(const config &cfg);

    /**
     * @brief 关闭日志器并释放线程池资源
     * @details 将缓冲区日志刷盘后释放资源，调用后所有
     * 日志接口不再产生输出，直到再次调用 init。
     */
    void shutdown();

    /**
     * @brief 获取当前日志器
     * @return 全局日志器的 shared_ptr，未初始化则为空
     * @details 提供对底层 spdlog 日志器的直接访问，
     * 用于高级场景如自定义 sink、手动刷盘等。
     */
    [[nodiscard]] auto recorder() noexcept -> std::shared_ptr<spdlog::logger>;

    // ─── 内部实现 ────────────────────────────────

    namespace detail
    {

        /**
         * @brief 日志输出内部实现
         * @tparam Fields 编译期字段链（NTTP）
         * @param lvl spdlog 日志等级
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @details 渲染前缀到栈上 scratch_pad，通过 std::string_view
         * 传递给 spdlog，零堆分配。前缀为空时跳过拼接。
         */
        template <auto Fields>
        auto log_impl(spdlog::level::level_enum lvl,
                      std::string_view fmt, auto &&...args) -> void
        {
            if (const auto rec = recorder())
            {
                scratch_pad buf;
                render_prefix<decltype(Fields)>(buf);
                if (buf.empty())
                {
                    rec->log(lvl, spdlog::fmt_lib::runtime(fmt),
                             std::forward<decltype(args)>(args)...);
                }
                else
                {
                    rec->log(lvl, spdlog::fmt_lib::runtime("{}" + std::string(fmt)),
                             std::string_view(buf.c_str(),
                                              static_cast<std::size_t>(buf.pos)),
                             std::forward<decltype(args)>(args)...);
                }
            }
        }

    } // namespace detail

    // ─── debug ──────────────────────────────────

    /**
     * @brief 记录调试日志（默认字段：sid + protocol）
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串，支持 fmt 库语法
     * @param args 格式化参数
     */
    template <typename... Args>
    auto debug(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<level_default::debug>(
            spdlog::level::debug, fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief 记录调试日志（自定义字段）
     * @tparam Fields 字段管道，如 field::sid | field::protocol
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串
     * @param args 格式化参数
     */
    template <field::field_or_chain auto Fields, typename... Args>
    auto debug(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<field::normalize(Fields)>(
            spdlog::level::debug, fmt, std::forward<Args>(args)...);
    }

    // ─── info ───────────────────────────────────

    /**
     * @brief 记录信息日志（默认字段：sid）
     */
    template <typename... Args>
    auto info(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<level_default::info>(
            spdlog::level::info, fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief 记录信息日志（自定义字段）
     */
    template <field::field_or_chain auto Fields, typename... Args>
    auto info(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<field::normalize(Fields)>(
            spdlog::level::info, fmt, std::forward<Args>(args)...);
    }

    // ─── warn ───────────────────────────────────

    /**
     * @brief 记录警告日志（默认字段：sid + client + protocol）
     */
    template <typename... Args>
    auto warn(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<level_default::warn>(
            spdlog::level::warn, fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief 记录警告日志（自定义字段）
     */
    template <field::field_or_chain auto Fields, typename... Args>
    auto warn(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<field::normalize(Fields)>(
            spdlog::level::warn, fmt, std::forward<Args>(args)...);
    }

    // ─── error ──────────────────────────────────

    /**
     * @brief 记录错误日志（默认字段：全部）
     */
    template <typename... Args>
    auto error(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<level_default::error>(
            spdlog::level::err, fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief 记录错误日志（自定义字段）
     */
    template <field::field_or_chain auto Fields, typename... Args>
    auto error(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<field::normalize(Fields)>(
            spdlog::level::err, fmt, std::forward<Args>(args)...);
    }

    // ─── fatal ──────────────────────────────────

    /**
     * @brief 记录致命错误日志（默认字段：全部）
     * @warning 致命错误通常意味着程序即将终止，
     * 但此函数不会自动终止程序。
     */
    template <typename... Args>
    auto fatal(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<level_default::error>(
            spdlog::level::critical, fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief 记录致命错误日志（自定义字段）
     */
    template <field::field_or_chain auto Fields, typename... Args>
    auto fatal(std::string_view fmt, Args &&...args) -> void
    {
        detail::log_impl<field::normalize(Fields)>(
            spdlog::level::critical, fmt, std::forward<Args>(args)...);
    }

} // namespace psm::trace
