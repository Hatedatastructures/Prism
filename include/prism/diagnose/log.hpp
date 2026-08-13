/**
 * @file spdlog.hpp
 * @brief 日志接口封装
 * @details 封装 spdlog，提供统一日志接口。支持 shared_ptr<context>
 *          和 context& 两种传参方式，nullptr 安全。
 *          所有接口内部捕获异常，日志失败不影响业务逻辑。
 */
#pragma once

#include <prism/diagnose/config.hpp>
#include <prism/diagnose/context.hpp>

// 注意：access 级别（值 7）超出 spdlog 编译库的 level_names 表（仅 7 项），
// pattern 含 %l 时格式化会越界。spdlog.cpp init 在 access 模式下把 %l 替换为
// 固定 "access"；非 access 模式下 access() 自动降级为 info 记录，避免越界。
#include <spdlog/spdlog.h>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace psm::diagnose
{

    // 自定义最高级别（值 7，高于 off）：仅 IP/连接统计（访问日志）。
    // log_level="access" 时 set_level(7) 只记录本级别，warn/err 等一律不显示。
    inline constexpr auto access_level = static_cast<spdlog::level::level_enum>(7);

    void mdc_set(const std::string &key, const std::string &value);
    void mdc_remove(const std::string &key);
    void mdc_clear();

    /**
     * @brief 构建 MDC 前缀字符串
     * @return 由 MDC 键值对拼装的日志前缀，空 MDC 返回空串
     */
    [[nodiscard]] auto build_mdc_prefix() -> std::string;

    /**
     * @brief 初始化日志系统
     * @param cfg 日志配置（文件/控制台/级别等）
     */
    void init(const config &cfg);
    void shutdown();

    /**
     * @brief 获取当前日志记录器
     * @return 共享的 spdlog logger 指针，未初始化时为空
     */
    [[nodiscard]] auto recorder() noexcept -> std::shared_ptr<spdlog::logger>;

    namespace detail
    {
        template <typename... Args>
        auto log(const char *pfx, spdlog::level::level_enum lvl, std::string_view fmt, Args &&...args) -> void
        {
            if (const auto rec = recorder())
            {
                if (pfx)
                {
                    rec->log(lvl, spdlog::fmt_lib::runtime("{} " + std::string(fmt)), pfx,
                             std::forward<Args>(args)...);
                }
                else
                {
                    rec->log(lvl, spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
                }
            }
        }
    } // namespace detail

    // ─── shared_ptr<context>（nullptr 安全）────────

    template <typename... Args>
    auto debug(const std::shared_ptr<context> &pfx, std::string_view fmt, Args &&...args) -> void
    {
        detail::log(pfx ? pfx->prefix() : nullptr, spdlog::level::debug, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto info(const std::shared_ptr<context> &pfx, std::string_view fmt, Args &&...args) -> void
    {
        detail::log(pfx ? pfx->prefix() : nullptr, spdlog::level::info, fmt, std::forward<Args>(args)...);
    }

    // ─── ip（IP/连接统计，最高优先级）────────
    // access 模式（log_level="access"）：以 access_level 记录，只显示本级别；
    // 其他模式：降级为 info 记录（访问日志在 info 级别仍可见）

    template <typename... Args>
    auto access(const std::shared_ptr<context> &pfx, std::string_view fmt, Args &&...args) -> void
    {
        const auto rec = recorder();
        if (!rec)
        {
            return;
        }
        const auto level = rec->level() >= access_level ? access_level : spdlog::level::info;
        detail::log(pfx ? pfx->prefix() : nullptr, level, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto warn(const std::shared_ptr<context> &pfx, std::string_view fmt, Args &&...args) -> void
    {
        detail::log(pfx ? pfx->prefix() : nullptr, spdlog::level::warn, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto error(const std::shared_ptr<context> &pfx, std::string_view fmt, Args &&...args) -> void
    {
        detail::log(pfx ? pfx->prefix() : nullptr, spdlog::level::err, fmt, std::forward<Args>(args)...);
    }

    // ─── context& ──────────────────────────

    template <typename... Args>
    auto debug(const context &pfx, std::string_view fmt, Args &&...args) -> void
    {
        detail::log(pfx.prefix(), spdlog::level::debug, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto info(const context &pfx, std::string_view fmt, Args &&...args) -> void
    {
        detail::log(pfx.prefix(), spdlog::level::info, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto access(const context &pfx, std::string_view fmt, Args &&...args) -> void
    {
        const auto rec = recorder();
        if (!rec)
        {
            return;
        }
        const auto level = rec->level() >= access_level ? access_level : spdlog::level::info;
        detail::log(pfx.prefix(), level, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto warn(const context &pfx, std::string_view fmt, Args &&...args) -> void
    {
        detail::log(pfx.prefix(), spdlog::level::warn, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto error(const context &pfx, std::string_view fmt, Args &&...args) -> void
    {
        detail::log(pfx.prefix(), spdlog::level::err, fmt, std::forward<Args>(args)...);
    }

    // ─── 无前缀 ──────────────────────────────────

    template <typename... Args>
    auto debug(std::string_view fmt, Args &&...args) -> void
    {
        detail::log(nullptr, spdlog::level::debug, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto info(std::string_view fmt, Args &&...args) -> void
    {
        detail::log(nullptr, spdlog::level::info, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto access(std::string_view fmt, Args &&...args) -> void
    {
        const auto rec = recorder();
        if (!rec)
        {
            return;
        }
        const auto level = rec->level() >= access_level ? access_level : spdlog::level::info;
        detail::log(nullptr, level, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto warn(std::string_view fmt, Args &&...args) -> void
    {
        detail::log(nullptr, spdlog::level::warn, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto error(std::string_view fmt, Args &&...args) -> void
    {
        detail::log(nullptr, spdlog::level::err, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    auto fatal(std::string_view fmt, Args &&...args) -> void
    {
        detail::log(nullptr, spdlog::level::critical, fmt, std::forward<Args>(args)...);
    }

} // namespace psm::diagnose
