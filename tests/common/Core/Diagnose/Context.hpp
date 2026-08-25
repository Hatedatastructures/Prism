/**
 * @file Context.hpp
 * @brief 会话级日志上下文
 * @details 7 字段前缀系统：worker、Stage、proto、scheme、Target、Conn、born。
 *          前缀缓存 + 版本号机制，字段不变时零开销返回缓存指针。
 *          born 在会话创建时 set_born() 一次，后续不再读时钟。
 *
 * 用法：
 *   auto ctx = std::make_shared<Context>();
 *   ctx->born = steady_clock::now();
 *   ctx->proto = "trojan";
 *   ctx->Bump();
 *   Diagnose::Debug(ctx, "msg");  // 前缀: [W0][S3][trojan][... 18:22:48.842]
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>

namespace Preview::Diagnose
{

    /// @brief 生命周期阶段
    enum class Stage : std::uint8_t
    {
        Accept = 0,
        Probe = 1,
        identify = 2,
        handshake = 3,
        forward = 4,
        Close = 5,
    };

    /**
 * @struct Context
 * @brief 诊断上下文
 * @details 承载日志前缀字段。shared_ptr 管理（IOCP 回调安全）。
 *          前缀缓存 + gen 版本号：字段变化时 Bump() 标记脏，Prefix() 按需渲染。
 */
    struct Context : public std::enable_shared_from_this<Context>
    {
        Context() = default;

        // 字段
        std::chrono::steady_clock::time_point born{};
        std::uint16_t worker = 0;
        std::uint8_t Stage = 0;
        char Target[48] = {};
        char proto[8] = {};
        char scheme[8] = {};
        std::uint64_t Conn = 0;

        /**
         * @brief 标记脏——字段变化后调用
         */
        auto Bump() noexcept -> void
        {
            CacheGen++;
        }

        /**
         * @brief 返回前缀指针（缓存命中直接返回，否则重新渲染）
         * @return 日志前缀指针
         */
        [[nodiscard]] auto Prefix() const -> const char *
        {
            if (CacheGen != RenderGen)
            {
                Render();
            }
            return cached;
        }

    private:
        auto Render() const noexcept -> void
        {
            RenderGen = CacheGen;
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(born.time_since_epoch()).count();
            auto sec = ms / 1000;
            auto hh = static_cast<int>((sec % 86400) / 3600);
            auto mm = static_cast<int>((sec % 3600) / 60);
            auto ss = static_cast<int>(sec % 60);
            std::snprintf(cached, sizeof(cached), "[W%u][S%u][%s][%s %02d:%02d:%02d.%03d]", worker, Stage,
                          proto, Target, hh, mm, ss, static_cast<int>(ms % 1000));
        }

        mutable char cached[80] = {};
        mutable std::uint8_t CacheGen = 0;
        mutable std::uint8_t RenderGen = 0;
    };

} // namespace Preview::Diagnose
