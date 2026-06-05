/**
 * @file context.hpp
 * @brief 会话级日志上下文
 * @details 提供编译期字段管道组合日志前缀机制。通过 operator| 管道语法
 * 选择输出字段，字段按管道顺序渲染，编译期完全展开，运行时零开销。
 *
 * 6 字段体系：conn、protocol、stream、scheme、user、phase
 * 没有值的字段不渲染，每行最多 2 个字段。
 *
 * 用法：
 *   trace::debug("msg");                                        // 默认无前缀
 *   trace::debug<flt::conn | flt::protocol>("msg");         // 自定义字段
 *
 * 扩展字段只需在 namespace flt 中添加 tag struct + constexpr 值。
 *
 * 纯 header-only，零外部依赖（不含 spdlog、boost）。
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>


namespace psm::trace
{

    // ─── 前向声明 ────────────────────────────────

    struct session_prefix;
    struct scratch_pad;

    // ─── 字段类型系统 ────────────────────────────

    /**
     * @brief 字段标签与管道组合
     * @details 每个字段定义一个 tag struct（含 static constexpr bit 和
     * static render()）和一个 inline constexpr 值。通过 operator| 管道
     * 组合，编译期构建 chain<Fs...> 类型链。运行时通过 fold expression
     * 按管道顺序展开渲染，零间接调用。
     */
    namespace flt
    {
        /// 字段类型约束：必须含 static constexpr bit 和 static active()
        template <typename T>
        concept field_type = requires(const session_prefix &p) {
            { T::bit } -> std::convertible_to<unsigned>;
            { T::active(p) } -> std::convertible_to<bool>;
        };

        // ---- 字段标签 ----

        struct conn_t
        {
            static constexpr unsigned bit = 1u << 0;
            static auto active(const session_prefix &p) noexcept -> bool;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct protocol_t
        {
            static constexpr unsigned bit = 1u << 1;
            static auto active(const session_prefix &p) noexcept -> bool;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct stream_t
        {
            static constexpr unsigned bit = 1u << 2;
            static auto active(const session_prefix &p) noexcept -> bool;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct scheme_t
        {
            static constexpr unsigned bit = 1u << 3;
            static auto active(const session_prefix &p) noexcept -> bool;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct user_t
        {
            static constexpr unsigned bit = 1u << 4;
            static auto active(const session_prefix &p) noexcept -> bool;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct phase_t
        {
            static constexpr unsigned bit = 1u << 5;
            static auto active(const session_prefix &p) noexcept -> bool;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        // ---- constexpr 值 ----

        inline constexpr conn_t     conn{};
        inline constexpr protocol_t protocol{};
        inline constexpr stream_t   stream{};
        inline constexpr scheme_t   scheme{};
        inline constexpr user_t     user{};
        inline constexpr phase_t    phase{};

        // ---- chain 类型 ----

        /// 编译期字段链，携带有序字段类型列表
        template <typename... Fs>
        struct chain
        {};

        // ---- operator| 重载 ----

        /// field | field → chain<F1, F2>
        template <field_type A, field_type B>
        consteval auto operator|(A, B) -> chain<A, B>
        {
            return {};
        }

        /// chain<...> | field → chain<..., F>
        template <typename... As, field_type B>
        consteval auto operator|(chain<As...>, B) -> chain<As..., B>
        {
            return {};
        }

        // ---- 约束 ----

        template <typename T>
        struct is_chain : std::false_type
        {};

        template <typename... Fs>
        struct is_chain<chain<Fs...>> : std::true_type
        {};

        /// 管道类型约束
        template <typename T>
        concept field_chain = is_chain<T>::value;

        /// 字段或管道
        template <typename T>
        concept field_or_chain = field_type<T> || field_chain<T>;

        // ---- 归一化 ----

        /// 单字段 → chain<F>
        template <field_type F>
        consteval auto normalize(F) -> chain<F>
        {
            return {};
        }

        /// 已是 chain → 直接返回
        template <typename... Fs>
        consteval auto normalize(chain<Fs...>) -> chain<Fs...>
        {
            return {};
        }

    } // namespace flt

    /**
     * @brief 日志等级默认字段链
     * @details 所有等级默认无前缀，调用方通过显式模板参数指定字段。
     * 启动日志、全局模块无需会话上下文。
     */
    namespace level_default
    {
        static constexpr auto debug = flt::chain<>{};
        static constexpr auto info  = flt::chain<>{};
        static constexpr auto warn  = flt::chain<>{};
        static constexpr auto error = flt::chain<>{};
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

        auto append(const char *s) noexcept -> void
        {
            while (*s && pos < static_cast<int>(capacity) - 1)
                data[pos++] = *s++;
        }

        auto append(std::uint64_t v) noexcept -> void
        {
            pos += std::snprintf(data + pos, capacity - pos,
                                 "%llu", static_cast<unsigned long long>(v));
        }

        auto append(std::uint32_t v) noexcept -> void
        {
            pos += std::snprintf(data + pos, capacity - pos,
                                 "%u", static_cast<unsigned>(v));
        }

        auto append(std::uint16_t v) noexcept -> void
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
     * @brief 阶段标注
     * @details 通过 set() 设置当前阶段（指向字符串字面量，零分配），
     * phase_t 字段渲染时输出 phase=xxx 格式。
     */
    struct phase_slot
    {
        const char *label = nullptr;

        [[nodiscard]] auto active() const noexcept -> bool
        {
            return label != nullptr;
        }

        auto set(const char *phase_label) noexcept -> void
        {
            label = phase_label;
        }

        auto clear() noexcept -> void
        {
            label = nullptr;
        }
    };

    /**
     * @struct session_prefix
     * @brief 会话前缀数据
     * @details 承载单个会话的诊断上下文（连接 ID、协议名、流 ID、
     * TLS 方案、用户名、阶段标注、处理单元名）。每个字段的渲染逻辑
     * 由对应的 field tag struct 的 static render() 方法实现，
     * 由 render_ordered 编译期展开。没有值的字段不渲染。
     */
    struct session_prefix
    {
        std::uint64_t conn_id = 0;
        char client[48] = {};
        std::uint16_t client_port = 0;
        char listen[48] = {};
        std::uint16_t listen_port = 0;
        char protocol[16] = {};
        std::uint32_t stream_id = 0;
        char scheme_name[16] = {};
        char user[32] = {};

        phase_slot phase;
    };

    // ─── 字段 active + render 实现 ──────────────

    namespace flt
    {

        inline auto conn_t::active(const session_prefix &p) noexcept -> bool
        {
            return p.conn_id != 0;
        }

        inline auto conn_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append("conn=");
            buf.append(p.conn_id);
        }

        inline auto protocol_t::active(const session_prefix &p) noexcept -> bool
        {
            return p.protocol[0] != '\0';
        }

        inline auto protocol_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append(p.protocol);
        }

        inline auto stream_t::active(const session_prefix &p) noexcept -> bool
        {
            return p.stream_id != 0;
        }

        inline auto stream_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append("stream=");
            buf.append(p.stream_id);
        }

        inline auto scheme_t::active(const session_prefix &p) noexcept -> bool
        {
            return p.scheme_name[0] != '\0';
        }

        inline auto scheme_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append(p.scheme_name);
        }

        inline auto user_t::active(const session_prefix &p) noexcept -> bool
        {
            return p.user[0] != '\0';
        }

        inline auto user_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append("user=");
            buf.append(p.user);
        }

        inline auto phase_t::active(const session_prefix &p) noexcept -> bool
        {
            return p.phase.active();
        }

        inline auto phase_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append("phase=");
            buf.append(p.phase.label);
        }

    } // namespace flt

    // ─── render_ordered — 按 chain 顺序展开（跳过无值字段） ──

    /**
     * @brief 渲染单个字段，返回是否实际渲染
     * @details 先检查 active()，为 false 时跳过渲染。
     */
    template <typename F>
    auto render_one(const session_prefix &p, scratch_pad &buf) noexcept -> bool
    {
        if (!F::active(p))
            return false;
        F::render(p, buf);
        return true;
    }

    /**
     * @brief 按 chain 顺序渲染字段到 scratch_pad
     * @details 通过 fold expression 编译期展开 chain<Fs...>，
     * 按管道顺序依次调用每个字段的 render()。
     * 没有值的字段跳过，全部字段无值时不输出任何内容。
     * 输出格式：[field1 field2 ...]
     * @param p 会话前缀数据
     * @param buf 栈缓冲区
     * @param ch 字段链（仅用于模板参数推导）
     */
    template <typename... Fs>
    auto render_ordered(const session_prefix &p, scratch_pad &buf,
                        flt::chain<Fs...> /*ch*/) noexcept -> void
    {
        bool sep = false;
        const auto start_pos = buf.pos;
        auto emit_field = [&](auto fn)
        {
            const auto before = buf.pos;
            fn();
            if (buf.pos > before)
            {
                if (sep)
                {
                    // 在已写入内容前插入空格
                    // 先把内容右移 1 字节
                    const auto len = buf.pos - before;
                    std::memmove(buf.data + before + 1, buf.data + before, len);
                    buf.data[before] = ' ';
                    buf.pos++;
                }
                sep = true;
            }
        };
        if constexpr (sizeof...(Fs) > 0)
        {
            (emit_field([&] { render_one<Fs>(p, buf); }), ...);
        }
        if (buf.pos > start_pos)
        {
            // 在已写入内容前插入 '['，末尾追加 ']'
            const auto len = buf.pos - start_pos;
            std::memmove(buf.data + start_pos + 1, buf.data + start_pos, len);
            buf.data[start_pos] = '[';
            buf.pos++;
            buf.data[buf.pos++] = ']';
            buf.data[buf.pos] = '\0';
        }
    }

    // ─── thread_local 上下文 ────────────────────

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    inline thread_local session_prefix *active_prefix = nullptr;

    /**
     * @class scope_guard
     * @brief 会话前缀 RAII 守卫
     * @details 构造时设置 active_prefix 为当前会话的前缀，
     * 析构时仅在 active_prefix 仍指向此前缀时清除为 nullptr。
     * 不保存/恢复旧值，避免多协程环境下产生悬垂指针。
     */
    class scope_guard
    {
    public:
        explicit scope_guard(session_prefix &pfx) noexcept
            : prefix_(&pfx)
        {
            active_prefix = &pfx;
        }

        ~scope_guard() noexcept
        {
            if (active_prefix == prefix_)
                active_prefix = nullptr;
        }

        scope_guard(const scope_guard &) = delete;
        auto operator=(const scope_guard &) -> scope_guard & = delete;
        scope_guard(scope_guard &&) = delete;
        auto operator=(scope_guard &&) -> scope_guard & = delete;

    private:
        session_prefix *prefix_;
    };

    /**
     * @brief 渲染当前线程的会话前缀到 scratch_pad
     * @tparam Chain 字段链类型（由 level_default 或用户 pipe 生成）
     * @param buf 栈缓冲区，由调用方持有
     * @details 无活跃前缀时 buf 不变。零堆分配。
     */
    template <typename Chain>
    auto render_prefix(scratch_pad &buf) noexcept -> void
    {
        if (active_prefix)
            render_ordered(*active_prefix, buf, Chain{});
    }

} // namespace psm::trace
