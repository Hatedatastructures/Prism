/**
 * @file context.hpp
 * @brief 会话级日志上下文
 * @details 7 字段前缀系统：worker、stage、proto、scheme、target、conn、born。
 *          前缀缓存 + 版本号机制，字段不变时零开销返回缓存指针。
 *          born 在会话创建时 set_born() 一次，后续不再读时钟。
 *
 * 用法：
 *   auto ctx = std::make_shared<context>();
 *   ctx->born = steady_clock::now();
 *   ctx->proto = "trojan";
 *   ctx->bump();
 *   diagnose::debug(ctx, "msg");  // 前缀: [W0][S3][trojan][... 18:22:48.842]
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>

namespace psm::diagnose
{

    /// @brief 生命周期阶段
    enum class stage : std::uint8_t
    {
        accept = 0,
        probe = 1,
        identify = 2,
        handshake = 3,
        forward = 4,
        close = 5,
    };

    /**
 * @struct context
 * @brief 诊断上下文
 * @details 承载日志前缀字段。shared_ptr 管理（IOCP 回调安全）。
 *          前缀缓存 + gen 版本号：字段变化时 bump() 标记脏，prefix() 按需渲染。
 */
    struct context : public std::enable_shared_from_this<context>
    {
        context() = default;

        // 字段
        std::chrono::steady_clock::time_point born{};
        std::uint16_t worker = 0;
        std::uint8_t stage = 0;
        char target[48] = {};
        char proto[8] = {};
        char scheme[8] = {};
        std::uint64_t conn = 0;

        /**
         * @brief 标记脏——字段变化后调用
         */
        auto bump() noexcept -> void
        {
            cache_gen++;
        }

        /**
         * @brief 返回前缀指针（缓存命中直接返回，否则重新渲染）
         * @return 日志前缀指针
         */
        [[nodiscard]] auto prefix() const -> const char *
        {
            if (cache_gen != render_gen)
            {
                render();
            }
            return cached;
        }

    private:
        auto render() const noexcept -> void
        {
            render_gen = cache_gen;
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(born.time_since_epoch()).count();
            auto sec = ms / 1000;
            auto hh = static_cast<int>((sec % 86400) / 3600);
            auto mm = static_cast<int>((sec % 3600) / 60);
            auto ss = static_cast<int>(sec % 60);
            std::snprintf(cached, sizeof(cached), "[W%u][S%u][%s][%s %02d:%02d:%02d.%03d]", worker, stage,
                          proto, target, hh, mm, ss, static_cast<int>(ms % 1000));
        }

        mutable char cached[80] = {};
        mutable std::uint8_t cache_gen = 0;
        mutable std::uint8_t render_gen = 0;
    };

} // namespace psm::diagnose
