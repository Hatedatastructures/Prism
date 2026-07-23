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
#include <memory>
#include <string>
#include <type_traits>


namespace psm::trace
{

    // ─── 前向声明 ────────────────────────────────

    struct trace_context;
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
        concept field_type = requires(const trace_context &p) {
            { T::bit } -> std::convertible_to<unsigned>;
            { T::active(p) } -> std::convertible_to<bool>;
        };

        // ---- 字段标签 ----

        struct conn_t
        {
            static constexpr unsigned bit = 1u << 0;
            static auto active(const trace_context &p) noexcept -> bool;
            static auto render(const trace_context &p, scratch_pad &buf) noexcept -> void;
        };

        struct protocol_t
        {
            static constexpr unsigned bit = 1u << 1;
            static auto active(const trace_context &p) noexcept -> bool;
            static auto render(const trace_context &p, scratch_pad &buf) noexcept -> void;
        };

        struct stream_t
        {
            static constexpr unsigned bit = 1u << 2;
            static auto active(const trace_context &p) noexcept -> bool;
            static auto render(const trace_context &p, scratch_pad &buf) noexcept -> void;
        };

        struct scheme_t
        {
            static constexpr unsigned bit = 1u << 3;
            static auto active(const trace_context &p) noexcept -> bool;
            static auto render(const trace_context &p, scratch_pad &buf) noexcept -> void;
        };

        struct user_t
        {
            static constexpr unsigned bit = 1u << 4;
            static auto active(const trace_context &p) noexcept -> bool;
            static auto render(const trace_context &p, scratch_pad &buf) noexcept -> void;
        };

        struct phase_t
        {
            static constexpr unsigned bit = 1u << 5;
            static auto active(const trace_context &p) noexcept -> bool;
            static auto render(const trace_context &p, scratch_pad &buf) noexcept -> void;
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
     * @details 640 字节栈分配，零堆开销。用于 trace_context
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
     * @struct trace_context
     * @brief 诊断上下文（trace 用的会话/流/传输层标签载体）
     * @details 承载单条诊断链路的日志渲染字段（conn_id、stream_id、
     * scheme、protocol、user、phase）。每个字段的渲染逻辑由对应的
     * field tag struct 的 static render() 方法实现，由 render_ordered
     * 编译期展开。没有值的字段不渲染。
     *
     * 业务数据（端点/目标/路由决策）不在 trace_context，由
     * @ref psm::resources::request_metadata 承载。trace_context 与
     * metadata 并行流转，但职责分离。
     *
     * 不只用于 session：mux stream、transport 装饰器、protocol handler
     * 都可以持有 shared_ptr<trace_context>，在任意作用域内传递。
     *
     * @note 必须通过 std::shared_ptr 管理（继承 enable_shared_from_this）。
     * 原因：IOCP 回调通过 shared_ptr 副本
     * 保活 trace_context，防止协程挂起期间 session/core 析构导致
     * captured_prefix_ 悬垂。
     *
     * active 字段：retire() 标记退出。
     * 用于让 detached 协程检测"主上下文已退出"，跳过 trace 渲染。
     * 单线程内访问（worker-per-thread io_context），无需原子。
     *
     * 字段顺序：hot 字段（active/conn_id）前置，提升缓存命中率。
     */
    struct trace_context : public std::enable_shared_from_this<trace_context>
    {
        // 显式 public 默认构造：std::enable_shared_from_this 的默认构造是 protected，
        // 但派生类内部访问合法。此处显式声明为 public，让 std::array<trace_context, N>
        // 等聚合容器能正确构造（容器不是派生类，不能访问 protected 基类构造）
        trace_context() = default;

        // ── hot 字段（每次 trace 调用都读）──────────
        bool active{true};                 ///< 上下文是否活跃（retire() 标记退出）
        std::uint64_t conn_id{0};          ///< 连接唯一标识符（渲染最高频字段）
        std::uint32_t stream_id{0};        ///< mux 流 ID

        // ── 日志专用字段（flt::tag 渲染用）─────────
        char scheme_name[16]{};            ///< TLS 伪装方案名（flt::scheme_t::render）
        char protocol[16]{};               ///< 协议名（flt::protocol_t::render）
        char user[32]{};                   ///< 用户名（flt::user_t::render）

        phase_slot phase;                  ///< 阶段标注

        // 端点字段（client/listen/client_port/listen_port）已移到
        // psm::resources::request_metadata::src/dst

        /// 上下文是否仍活跃（未被 retire）
        [[nodiscard]] constexpr auto alive() const noexcept -> bool
        {
            return active;
        }

        /// 标记上下文退役（手动调用或 RAII）
        constexpr auto retire() noexcept -> void
        {
            active = false;
        }
    };

    // ─── 字段 active + render 实现 ──────────────

    namespace flt
    {

        inline auto conn_t::active(const trace_context &p) noexcept -> bool
        {
            return p.conn_id != 0;
        }

        inline auto conn_t::render(const trace_context &p, scratch_pad &buf) noexcept -> void
        {
            buf.append("conn=");
            buf.append(p.conn_id);
        }

        inline auto protocol_t::active(const trace_context &p) noexcept -> bool
        {
            return p.protocol[0] != '\0';
        }

        inline auto protocol_t::render(const trace_context &p, scratch_pad &buf) noexcept -> void
        {
            buf.append(p.protocol);
        }

        inline auto stream_t::active(const trace_context &p) noexcept -> bool
        {
            return p.stream_id != 0;
        }

        inline auto stream_t::render(const trace_context &p, scratch_pad &buf) noexcept -> void
        {
            buf.append("stream=");
            buf.append(p.stream_id);
        }

        inline auto scheme_t::active(const trace_context &p) noexcept -> bool
        {
            return p.scheme_name[0] != '\0';
        }

        inline auto scheme_t::render(const trace_context &p, scratch_pad &buf) noexcept -> void
        {
            buf.append(p.scheme_name);
        }

        inline auto user_t::active(const trace_context &p) noexcept -> bool
        {
            return p.user[0] != '\0';
        }

        inline auto user_t::render(const trace_context &p, scratch_pad &buf) noexcept -> void
        {
            buf.append("user=");
            buf.append(p.user);
        }

        inline auto phase_t::active(const trace_context &p) noexcept -> bool
        {
            return p.phase.active();
        }

        inline auto phase_t::render(const trace_context &p, scratch_pad &buf) noexcept -> void
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
    auto render_one(const trace_context &p, scratch_pad &buf) noexcept -> bool
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
    auto render_ordered(const trace_context &p, scratch_pad &buf,
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

    // ─── 显式 prefix 渲染 ────────────────────

    /**
     * @brief 从显式 prefix 渲染到 scratch_pad（不读 thread_local）
     * @tparam Chain 字段链类型
     * @param buf 栈缓冲区
     * @param pfx 显式传入的会话前缀
     * @details 不渲染前缀（区别于 render_prefix_from），此版本从参数取 prefix，
     * 不依赖 thread_local（已删除）。
     */
    template <typename Chain>
    auto render_prefix_from(scratch_pad &buf, const trace_context &pfx) noexcept -> void
    {
        if (pfx.alive())
            render_ordered(pfx, buf, Chain{});
    }

} // namespace psm::trace
