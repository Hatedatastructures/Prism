/**
 * @file Log.hpp
 * @brief Preview 日志兼容 facade。
 * @details owner-aware 重载将值快照提交给异步 Logger；旧的无 owner 重载
 *          保持空操作，避免引入隐藏的全局 logger 生命周期。
 */

#pragma once

#include <memory>
#include <string_view>

#include <Preview/Foundation/Utility/Diagnose/Context.hpp>
#include <Preview/Foundation/Utility/Diagnose/Logger.hpp>

namespace Preview::Diagnose
{

    inline auto Submit(const Logger::Owner &Owner,
                       const LogLevel Level,
                       const std::shared_ptr<const TraceContext> &ContextOwner,
                       const std::string_view Message) noexcept -> EnqueueStatus
    {
        if (!Owner)
        {
            return EnqueueStatus::Stopped;
        }
        return Owner->TryWrite(Level, Message, ContextOwner ? ContextOwner->Snapshot()
                                                              : Preview::Statistics::TraceSnapshot{});
    }

    /** @brief owner-aware Debug 日志；上下文按值快照进入异步队列。 */
    inline auto Debug(const Logger::Owner &Owner,
                      const std::shared_ptr<const TraceContext> &ContextOwner,
                      const std::string_view Message) noexcept -> EnqueueStatus
    {
        return Submit(Owner, LogLevel::Debug, ContextOwner, Message);
    }

    /** @brief owner-aware Info 日志；上下文按值快照进入异步队列。 */
    inline auto Info(const Logger::Owner &Owner,
                     const std::shared_ptr<const TraceContext> &ContextOwner,
                     const std::string_view Message) noexcept -> EnqueueStatus
    {
        return Submit(Owner, LogLevel::Info, ContextOwner, Message);
    }

    /** @brief owner-aware Access 日志；上下文按值快照进入异步队列。 */
    inline auto Access(const Logger::Owner &Owner,
                       const std::shared_ptr<const TraceContext> &ContextOwner,
                       const std::string_view Message) noexcept -> EnqueueStatus
    {
        return Submit(Owner, LogLevel::Access, ContextOwner, Message);
    }

    /** @brief owner-aware Warn 日志；上下文按值快照进入异步队列。 */
    inline auto Warn(const Logger::Owner &Owner,
                     const std::shared_ptr<const TraceContext> &ContextOwner,
                     const std::string_view Message) noexcept -> EnqueueStatus
    {
        return Submit(Owner, LogLevel::Warn, ContextOwner, Message);
    }

    /** @brief owner-aware Error 日志；上下文按值快照进入异步队列。 */
    inline auto Error(const Logger::Owner &Owner,
                      const std::shared_ptr<const TraceContext> &ContextOwner,
                      const std::string_view Message) noexcept -> EnqueueStatus
    {
        return Submit(Owner, LogLevel::Error, ContextOwner, Message);
    }

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
