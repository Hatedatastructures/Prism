/**
 * @file context.hpp
 * @brief 会话级日志上下文
 * @details 提供编译期字段管道组合日志前缀机制。通过 operator| 管道语法
 * 选择输出字段，字段按管道顺序渲染，编译期完全展开，运行时零开销。
 *
 * 用法：
 *   trace::debug("msg");                                    // 默认字段
 *   trace::debug<field::sid | field::protocol>("msg");      // 自定义字段
 *   trace::debug<field::protocol | field::sid>("msg");      // 反序输出
 *
 * 扩展字段只需在 namespace field 中添加 tag struct + constexpr 值。
 *
 * 纯 header-only，零外部依赖（不含 spdlog、boost）。
 */

#pragma once

#include <cstdint>
#include <cstdio>
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
    namespace field
    {
        /// 字段类型约束：必须含 static constexpr bit
        template <typename T>
        concept field_type = requires { { T::bit } -> std::convertible_to<unsigned>; };

        // ---- 字段标签 ----

        struct sid_t
        {
            static constexpr unsigned bit = 1u << 0;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct client_t
        {
            static constexpr unsigned bit = 1u << 1;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct listen_t
        {
            static constexpr unsigned bit = 1u << 2;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct protocol_t
        {
            static constexpr unsigned bit = 1u << 3;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        struct phase_t
        {
            static constexpr unsigned bit = 1u << 4;
            static auto render(const session_prefix &p, scratch_pad &buf) noexcept -> void;
        };

        // ---- constexpr 值 ----

        inline constexpr sid_t      sid{};
        inline constexpr client_t   client{};
        inline constexpr listen_t   listen{};
        inline constexpr protocol_t protocol{};
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

    } // namespace field

    /**
     * @brief 日志等级默认字段链
     * @details 每个日志等级绑定一组默认字段，debug 输出最少，
     * error 输出全部字段用于排查。
     */
    namespace level_default
    {
        static constexpr auto debug = field::chain<field::sid_t, field::protocol_t>{};
        static constexpr auto info  = field::chain<field::sid_t>{};
        static constexpr auto warn  = field::chain<field::sid_t, field::client_t,
                                                     field::protocol_t>{};
        static constexpr auto error = field::chain<field::sid_t, field::client_t,
                                                    field::listen_t, field::protocol_t,
                                                    field::phase_t>{};
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
     * phase_t 字段渲染时输出 [label] 格式。
     */
    struct phase_slot
    {
        const char *label = nullptr;

        auto render(scratch_pad &buf) const noexcept -> void
        {
            if (label)
            {
                buf.append("[");
                buf.append(label);
                buf.append("]");
            }
        }

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
     * @details 承载单个会话的诊断上下文（会话 ID、客户端/监听端点、
     * 协议名、阶段标注）。每个字段的渲染逻辑由对应的 field tag struct
     * 的 static render() 方法实现，由 render_ordered 编译期展开。
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
    };

    // ─── 字段 render 实现 ──────────────────────

    namespace field
    {

        inline auto sid_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append("sid=");
            buf.append(p.session_id);
        }

        inline auto client_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append(p.client);
            buf.append(":");
            buf.append(p.client_port);
        }

        inline auto listen_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append(p.listen);
            buf.append(":");
            buf.append(p.listen_port);
        }

        inline auto protocol_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            buf.append(p.protocol);
        }

        inline auto phase_t::render(const session_prefix &p, scratch_pad &buf) noexcept -> void
        {
            p.phase.render(buf);
        }

    } // namespace field

    // ─── render_ordered — 按 chain 顺序展开 ──────

    /// 渲染单个字段
    template <typename F>
    auto render_one(const session_prefix &p, scratch_pad &buf) noexcept -> void
    {
        F::render(p, buf);
    }

    /**
     * @brief 按 chain 顺序渲染字段到 scratch_pad
     * @details 通过 fold expression 编译期展开 chain<Fs...>，
     * 按管道顺序依次调用每个字段的 render()。输出格式：[field1 field2 ...]
     * @param p 会话前缀数据
     * @param buf 栈缓冲区
     * @param ch 字段链（仅用于模板参数推导）
     */
    template <typename... Fs>
    auto render_ordered(const session_prefix &p, scratch_pad &buf,
                        field::chain<Fs...> /*ch*/) noexcept -> void
    {
        buf.append("[");
        bool sep = false;
        auto emit_field = [&](auto fn)
        {
            if (sep)
                buf.append(" ");
            fn();
            sep = true;
        };
        if constexpr (sizeof...(Fs) > 0)
        {
            (emit_field([&] { render_one<Fs>(p, buf); }), ...);
        }
        buf.append("]");
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
