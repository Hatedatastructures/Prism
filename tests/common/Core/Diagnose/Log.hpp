/**
 * @file log.hpp
 * @brief 轻量日志 stub（测试库用）
 * @details 对齐主库 psm::diagnose 的日志接口签名，但实现为空操作：
 *          测试环境不依赖 spdlog。后续需要日志输出时，可将本文件
 *          替换为 spdlog 实现或接入测试日志框架。
 * @note 所有函数均为模板，编译期零开销（空实现）。
 */

#pragma once

#include <memory>
#include <string_view>

#include <common/Core/Diagnose/Context.hpp>

namespace Preview::Diagnose
{

    /**
     * @brief Debug 级别日志（空实现）
     * @tparam Args 格式化参数类型
     * @param pfx 日志前缀上下文
     * @param fmt 格式化字符串
     * @param args 格式化参数
     */
    template <typename... Args>
    inline auto Debug(const std::shared_ptr<Context> & /*pfx*/, std::string_view /*fmt*/,
                      Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Info 级别日志（空实现）
     */
    template <typename... Args>
    inline auto Info(const std::shared_ptr<Context> & /*pfx*/, std::string_view /*fmt*/,
                     Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Access 级别日志（空实现）
     */
    template <typename... Args>
    inline auto Access(const std::shared_ptr<Context> & /*pfx*/, std::string_view /*fmt*/,
                       Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Warn 级别日志（空实现）
     */
    template <typename... Args>
    inline auto Warn(const std::shared_ptr<Context> & /*pfx*/, std::string_view /*fmt*/,
                     Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Error 级别日志（空实现）
     */
    template <typename... Args>
    inline auto Error(const std::shared_ptr<Context> & /*pfx*/, std::string_view /*fmt*/,
                      Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Debug 级别日志（引用版，空实现）
     */
    template <typename... Args>
    inline auto Debug(const Context & /*pfx*/, std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Warn 级别日志（引用版，空实现）
     */
    template <typename... Args>
    inline auto Warn(const Context & /*pfx*/, std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Error 级别日志（引用版，空实现）
     */
    template <typename... Args>
    inline auto Error(const Context & /*pfx*/, std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Debug 级别日志（无前缀版，空实现）
     */
    template <typename... Args>
    inline auto Debug(std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Warn 级别日志（无前缀版，空实现）
     */
    template <typename... Args>
    inline auto Warn(std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief Error 级别日志（无前缀版，空实现）
     */
    template <typename... Args>
    inline auto Error(std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

} // namespace Preview::Diagnose
