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

#include <common/core/diagnose/context.hpp>

namespace psm::diagnose
{

    /**
     * @brief debug 级别日志（空实现）
     * @tparam Args 格式化参数类型
     * @param pfx 日志前缀上下文
     * @param fmt 格式化字符串
     * @param args 格式化参数
     */
    template <typename... Args>
    inline auto debug(const std::shared_ptr<context> & /*pfx*/, std::string_view /*fmt*/,
                      Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief info 级别日志（空实现）
     */
    template <typename... Args>
    inline auto info(const std::shared_ptr<context> & /*pfx*/, std::string_view /*fmt*/,
                     Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief access 级别日志（空实现）
     */
    template <typename... Args>
    inline auto access(const std::shared_ptr<context> & /*pfx*/, std::string_view /*fmt*/,
                       Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief warn 级别日志（空实现）
     */
    template <typename... Args>
    inline auto warn(const std::shared_ptr<context> & /*pfx*/, std::string_view /*fmt*/,
                     Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief error 级别日志（空实现）
     */
    template <typename... Args>
    inline auto error(const std::shared_ptr<context> & /*pfx*/, std::string_view /*fmt*/,
                      Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief debug 级别日志（引用版，空实现）
     */
    template <typename... Args>
    inline auto debug(const context & /*pfx*/, std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief warn 级别日志（引用版，空实现）
     */
    template <typename... Args>
    inline auto warn(const context & /*pfx*/, std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief error 级别日志（引用版，空实现）
     */
    template <typename... Args>
    inline auto error(const context & /*pfx*/, std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief debug 级别日志（无前缀版，空实现）
     */
    template <typename... Args>
    inline auto debug(std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief warn 级别日志（无前缀版，空实现）
     */
    template <typename... Args>
    inline auto warn(std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

    /**
     * @brief error 级别日志（无前缀版，空实现）
     */
    template <typename... Args>
    inline auto error(std::string_view /*fmt*/, Args &&... /*args*/) noexcept -> void
    {
    }

} // namespace psm::diagnose
