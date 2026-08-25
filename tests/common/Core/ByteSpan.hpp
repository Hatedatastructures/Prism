/**
 * @file byte_span.hpp
 * @brief 字节视图转换工具（零拷贝 span 家族）
 * @details 提供容器/字符串 ↔ std::span 的无拷贝视图转换，消除散落的
 * reinterpret_cast 强转。统一模板 As<To> 以模板参数控制目标元素类型
 * （std::byte / std::uint8_t / char 等），源类型任意（span/string/
 * string_view/vector/array）：const 源产生 const 视图，可变源产生
 * 可变视图（可作为写缓冲，如 HTTP 读缓冲）：
 *          - As<std::uint8_t>：任意 byte/char 源 → uint8_t 视图
 *          - As<std::byte>：任意 uint8_t/char 源 → byte 视图
 *          - As<To>(ptr, len)：裸指针 + 长度 → 只读视图
 *          - AsStrView：字节视图 → string_view
 * 便捷名 AsBytes / AsU8 / AsU8Span / AsBytesSpan 等价于
 * As<std::byte> / As<std::uint8_t>，保持既有调用点不变。
 * @note AsBytes 的 span 重载刻意保持非模板：C++23 标准库的
 * std::asBytes(span) 会经 ADL 参与重载决议，非模板重载优先，
 * 保证既有无限定调用点解析稳定。
 * @note 仅指针重解释，不复制数据；调用方保证生命周期存续。
 * @note 所有函数 inline + [[nodiscard]] + noexcept，零开销。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace Preview
{

    namespace detail
    {
        /**
         * @brief 单字节平凡元素（std::byte / uint8_t / char 等）
         * @tparam T 候选元素类型
         */
        template <typename T>
        concept ByteElement = sizeof(T) == 1 && std::is_trivially_copyable_v<T>;

        /**
         * @brief 单字节元素指针（byte / uint8_t / char 指针）
         * @tparam T 候选指针类型
         */
        template <typename T>
        concept BytePointer = std::is_pointer_v<T> && ByteElement<std::remove_pointer_t<T>>;

        /**
         * @brief 非 const 单字节元素指针（可写）
         * @tparam T 候选指针类型
         */
        template <typename T>
        concept MutableBytePointer = BytePointer<T> && (!std::is_const_v<std::remove_pointer_t<T>>);

        /**
         * @brief 只读字节源（Data() 返回单字节指针 + Size()）
         * @tparam C 源类型
         */
        template <typename C>
        concept ByteSource = requires(const C &c) 
        {
            { c.data() } -> BytePointer;
            c.size();
        };

        /**
         * @brief 可变字节源（Data() 返回非 const 单字节指针 + Size()）
         * @tparam C 源类型
         */
        template <typename C>
        concept MutableByteSource = requires(C &c) 
        {
            { c.data() } -> MutableBytePointer;
            c.size();
        };
    } // namespace detail

    // ── 统一转换 As<To>：目标元素类型由模板参数控制 ──

    /**
     * @brief span 元素转换（可变源 → 可变视图）
     * @details 同时覆盖 dynamic 与 fixed extent 的 span。
     * @tparam To 目标元素类型（byte/uint8_t/char）
     * @tparam From 源元素类型（非 const）
     * @tparam E 源 span extent
     * @param s 源 span
     * @return To 视图（大小不变）
     */
    template <detail::ByteElement To, detail::ByteElement From, std::size_t E>
        requires (!std::is_const_v<From>)
    [[nodiscard]] inline auto As(std::span<From, E> s) noexcept 
        -> std::span<To>
    {
        return {reinterpret_cast<To *>(s.data()), s.size()};
    }

    /**
     * @brief span 元素转换（只读源 → 只读视图）
     * @details 同时覆盖 dynamic 与 fixed extent 的 span。
     * @tparam To 目标元素类型（byte/uint8_t/char）
     * @tparam From 源元素类型
     * @tparam E 源 span extent
     * @param s 源 span（const 元素）
     * @return const To 视图（大小不变）
     */
    template <detail::ByteElement To, detail::ByteElement From, std::size_t E>
    [[nodiscard]] inline auto As(std::span<const From, E> s) noexcept 
        -> std::span<const To>
    {
        return {reinterpret_cast<const To *>(s.data()), s.size()};
    }

    /**
     * @brief 可变容器/字符串 → 可变视图
     * @details 覆盖 span/string/vector/array 等含 Data()/Size() 的可变对象，
     * 返回值可作写缓冲（如 AsyncReadSome 读入）。
     * @tparam To 目标元素类型（byte/uint8_t/char）
     * @tparam C 源容器类型（元素非 const）
     * @param c 源容器
     * @return To 可变视图
     */
    template <detail::ByteElement To, detail::MutableByteSource C>
    [[nodiscard]] inline auto As(C &c) noexcept 
        -> std::span<To>
    {
        return {reinterpret_cast<To *>(c.data()), c.size()};
    }

    /**
     * @brief 只读容器/字符串 → 只读视图
     * @tparam To 目标元素类型（byte/uint8_t/char）
     * @tparam C 源容器类型
     * @param c 源容器（const 或只读）
     * @return const To 视图
     */
    template <detail::ByteElement To, detail::ByteSource C>
    [[nodiscard]] inline auto As(const C &c) noexcept 
        -> std::span<const To>
    {
        return {reinterpret_cast<const To *>(c.data()), c.size()};
    }

    /**
     * @brief 裸指针 + 长度 → 只读视图
     * @tparam To 目标元素类型（byte/uint8_t/char）
     * @param Data 字节指针
     * @param len 元素数
     * @return const To 视图
     */
    template <detail::ByteElement To>
    [[nodiscard]] inline auto As(const char *Data, std::size_t len) noexcept 
        -> std::span<const To>
    {
        return {reinterpret_cast<const To *>(Data), len};
    }

    // ── 便捷名（保持既有调用点不变）──

    /**
     * @brief uint8_t 写视图 → byte 写视图（As<std::byte> 便捷名）
     * @details 非模板重载：与 C++23 std::asBytes(span) 经 ADL 竞争时
     * 非模板优先，保证既有无限定调用点解析稳定。
     * @param s uint8_t 视图
     * @return byte 视图（大小不变）
     */
    [[nodiscard]] inline auto AsBytes(std::span<std::uint8_t> s) noexcept 
        -> std::span<std::byte>
    {
        return {reinterpret_cast<std::byte *>(s.data()), s.size()};
    }

    /**
     * @brief uint8_t 只读视图 → byte 只读视图（As<std::byte> 便捷名）
     * @param s uint8_t 只读视图
     * @return byte 只读视图（大小不变）
     */
    [[nodiscard]] inline auto AsBytes(std::span<const std::uint8_t> s) noexcept 
        -> std::span<const std::byte>
    {
        return {reinterpret_cast<const std::byte *>(s.data()), s.size()};
    }

    /**
     * @brief byte 目标便捷名（等价 As<std::byte>，容器/字符串源）
     * @details span<u8>/span<const u8> 实参走上方非模板重载；
     * 此处覆盖 string/string_view/vector/array 等源。
     * @tparam C 源类型
     * @param c 源
     * @return 目标视图（可变源 → 可变，只读源 → 只读）
     */
    template <typename C>
    [[nodiscard]] inline auto AsBytes(C &&c) noexcept 
        -> decltype(As<std::byte>(std::forward<C>(c)))
    {
        return As<std::byte>(std::forward<C>(c));
    }

    /**
     * @brief uint8_t 目标便捷名（等价 As<std::uint8_t>）
     * @tparam C 源类型（span/string/string_view/容器）
     * @param c 源
     * @return 目标视图（可变源 → 可变，只读源 → 只读）
     */
    template <typename C>
    [[nodiscard]] inline auto AsU8(C &&c) noexcept 
        -> decltype(As<std::uint8_t>(std::forward<C>(c)))
    {
        return As<std::uint8_t>(std::forward<C>(c));
    }

    /**
     * @brief uint8_t 视图便捷名（等价 As<std::uint8_t>）
     * @tparam C 源类型（span/string/string_view/容器）
     * @param c 源
     * @return 目标视图（可变源 → 可变，只读源 → 只读）
     */
    template <typename C>
    [[nodiscard]] inline auto AsU8Span(C &&c) noexcept 
        -> decltype(As<std::uint8_t>(std::forward<C>(c)))
    {
        return As<std::uint8_t>(std::forward<C>(c));
    }

    /**
     * @brief 字符指针 + 长度 → uint8_t 只读视图
     * @param Data 字符指针
     * @param len 元素数
     * @return uint8_t 视图（Size() 个元素）
     */
    [[nodiscard]] inline auto AsU8Span(const char *Data, std::size_t len) noexcept
        -> std::span<const std::uint8_t>
    {
        return As<std::uint8_t>(Data, len);
    }

    /**
     * @brief byte 视图便捷名（等价 As<std::byte>）
     * @tparam C 源类型（span/string/string_view/容器）
     * @param c 源
     * @return 目标视图（可变源 → 可变，只读源 → 只读）
     */
    template <typename C>
    [[nodiscard]] inline auto AsBytesSpan(C &&c) noexcept 
        -> decltype(As<std::byte>(std::forward<C>(c)))
    {
        return As<std::byte>(std::forward<C>(c));
    }

    /**
     * @brief 字符指针 + 长度 → byte 只读视图
     * @param Data 字符指针
     * @param len 元素数
     * @return byte 视图（Size() 个元素）
     */
    [[nodiscard]] inline auto AsBytesSpan(const char *Data, std::size_t len) noexcept
        -> std::span<const std::byte>
    {
        return As<std::byte>(Data, len);
    }

    /**
     * @brief 字节只读视图 → std::string_view
     * @param s uint8_t 视图
     * @return string_view（Size() 个字符）
     */
    [[nodiscard]] inline auto AsStrView(std::span<const std::uint8_t> s) noexcept 
        -> std::string_view
    {
        return {reinterpret_cast<const char *>(s.data()), s.size()};
    }

    /**
     * @brief byte 只读视图 → std::string_view
     * @param s byte 视图
     * @return string_view（Size() 个字符）
     */
    [[nodiscard]] inline auto AsStrView(std::span<const std::byte> s) noexcept 
        -> std::string_view
    {
        return AsStrView(AsU8(s));
    }

} // namespace Preview