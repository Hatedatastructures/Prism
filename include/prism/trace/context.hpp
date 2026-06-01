/**
 * @file context.hpp
 * @brief 会话级日志上下文
 * @details 提供字段选择性前缀渲染机制，根据日志等级自动选择
 * 输出字段（会话 ID、客户端地址、监听地址、协议、阶段）。
 * 纯 header-only，零外部依赖（不含 spdlog、boost）。
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <string>


namespace psm::trace
{

    /**
     * @brief 字段位掩码常量
     * @details 用于选择 session_prefix 渲染哪些字段，
     * 可通过位或组合多个字段。
     */
    namespace field
    {
        static constexpr unsigned sid      = 1u << 0;
        static constexpr unsigned client   = 1u << 1;
        static constexpr unsigned listen   = 1u << 2;
        static constexpr unsigned protocol = 1u << 3;
        static constexpr unsigned phase    = 1u << 4;

        static constexpr unsigned all     = sid | client | listen | protocol | phase;
        static constexpr unsigned minimal = sid;
    }

    /**
     * @brief 日志等级默认字段掩码
     * @details 每个日志等级绑定一组默认字段，debug 输出最少，
     * error 输出全部字段用于排查。
     */
    namespace level_default
    {
        static constexpr unsigned debug = field::sid | field::protocol;
        static constexpr unsigned info  = field::sid;
        static constexpr unsigned warn  = field::sid | field::client | field::protocol;
        static constexpr unsigned error = field::all;
    }

    /**
     * @struct scratch_pad
     * @brief 栈上格式化缓冲区
     * @details 640 字节栈分配，零堆开销。用于 session_prefix
     * 渲染前缀字符串，避免热路径上的堆分配。
     */
    struct scratch_pad
    {
        static constexpr auto capacity = 640;

        char data[capacity] = {};
        int pos = 0;

        void append(const char *s) noexcept
        {
            while (*s && pos < static_cast<int>(capacity) - 1)
                data[pos++] = *s++;
        }

        void append(std::uint64_t v) noexcept
        {
            pos += std::snprintf(data + pos, capacity - pos,
                                 "%llu", static_cast<unsigned long long>(v));
        }

        void append(std::uint16_t v) noexcept
        {
            pos += std::snprintf(data + pos, capacity - pos,
                                 "%u", static_cast<unsigned>(v));
        }

        [[nodiscard]] auto c_str() const noexcept -> const char *
        {
            return data;
        }

        [[nodiscard]] auto empty() const noexcept -> bool
        {
            return pos == 0;
        }
    };

    /**
     * @struct phase_slot
     * @brief 阶段标注占位
     * @details 初始集成为空实现，后续可扩展为支持自定义
     * 阶段标注（如 stealth/dial/tunnel 阶段）。
     */
    struct phase_slot
    {
        void render(scratch_pad & /*buf*/) const noexcept
        {
        }

        [[nodiscard]] auto active() const noexcept -> bool
        {
            return false;
        }
    };

    /**
     * @struct session_prefix
     * @brief 会话前缀数据
     * @details 承载单个会话的诊断上下文（会话 ID、客户端/监听端点、
     * 协议名、阶段标注）。render() 根据字段掩码选择性输出，
     * 避免每条日志输出全部字段。
     */
    struct session_prefix
    {
        std::uint64_t session_id = 0;
        char client[48] = {};
        std::uint16_t client_port = 0;
        char listen[48] = {};
        std::uint16_t listen_port = 0;
        char protocol[16] = {};

        phase_slot phase;

        void render(scratch_pad &buf, unsigned fields) const noexcept
        {
            bool need_sep = false;

            buf.append("[");
            if (fields & field::sid)
            {
                buf.append("sid=");
                buf.append(session_id);
                need_sep = true;
            }

            if (fields & field::client)
            {
                if (need_sep) buf.append(" ");
                buf.append(client);
                buf.append(":");
                buf.append(client_port);
                need_sep = true;
            }

            if (fields & field::listen)
            {
                if (need_sep) buf.append(" ");
                buf.append(listen);
                buf.append(":");
                buf.append(listen_port);
                need_sep = true;
            }

            if (fields & field::protocol)
            {
                if (need_sep) buf.append(" ");
                buf.append(protocol);
                need_sep = true;
            }

            buf.append("]");

            if (fields & field::phase)
            {
                phase.render(buf);
            }
        }
    };

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    inline thread_local session_prefix *active_prefix = nullptr;

    /**
     * @class scope_guard
     * @brief 会话前缀 RAII 守卫
     * @details 构造时保存当前 active_prefix 并设置新值，
     * 析构时恢复旧值。确保协程切换时前缀上下文正确。
     */
    class scope_guard
    {
    public:
        explicit scope_guard(session_prefix &pfx) noexcept
            : saved_(active_prefix)
        {
            active_prefix = &pfx;
        }

        ~scope_guard() noexcept
        {
            active_prefix = saved_;
        }

        scope_guard(const scope_guard &) = delete;
        auto operator=(const scope_guard &) -> scope_guard & = delete;
        scope_guard(scope_guard &&) = delete;
        auto operator=(scope_guard &&) -> scope_guard & = delete;

    private:
        session_prefix *saved_;
    };

    /**
     * @brief 渲染当前线程的会话前缀
     * @param fields 字段掩码，选择输出哪些字段
     * @return 格式化后的前缀字符串，无活跃前缀时返回空串
     */
    [[nodiscard]] inline auto build_prefix(unsigned fields) -> std::string
    {
        if (!active_prefix)
            return {};

        scratch_pad buf;
        active_prefix->render(buf, fields);
        if (buf.empty())
            return {};

        return {buf.c_str()};
    }

} // namespace psm::trace
