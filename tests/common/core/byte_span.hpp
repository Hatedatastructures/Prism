/**
 * @file byte_span.hpp
 * @brief 字节视图转换工具（零拷贝 span 家族）
 * @details 提供容器/字符串 ↔ std::span 的无拷贝视图转换，消除散落的
 * reinterpret_cast 强转：
 *          - as_bytes / as_u8：uint8_t ↔ byte 视图
 *          - as_u8_span：string / string_view / char* → uint8_t 视图
 *          - as_bytes_span：string / string_view / char* → byte 视图
 *          - as_str_view：字节视图 → string_view
 * @note 仅指针重解释，不复制数据；调用方保证生命周期存续。
 * @note 所有函数 inline + [[nodiscard]] + noexcept，零开销。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace psmtest
{

    /**
     * @brief uint8_t 写视图 → byte 写视图
     * @param s uint8_t 视图
     * @return byte 视图（大小不变）
     */
    [[nodiscard]] inline auto as_bytes(std::span<std::uint8_t> s) noexcept -> std::span<std::byte>
    {
        return {reinterpret_cast<std::byte *>(s.data()), s.size()};
    }

    /**
     * @brief uint8_t 只读视图 → byte 只读视图
     * @param s uint8_t 视图
     * @return byte 视图（大小不变）
     */
    [[nodiscard]] inline auto as_bytes(std::span<const std::uint8_t> s) noexcept -> std::span<const std::byte>
    {
        return {reinterpret_cast<const std::byte *>(s.data()), s.size()};
    }

    /**
     * @brief byte 写视图 → uint8_t 写视图
     * @param s byte 视图
     * @return uint8_t 视图（大小不变）
     */
    [[nodiscard]] inline auto as_u8(std::span<std::byte> s) noexcept -> std::span<std::uint8_t>
    {
        return {reinterpret_cast<std::uint8_t *>(s.data()), s.size()};
    }

    /**
     * @brief byte 只读视图 → uint8_t 只读视图
     * @param s byte 视图
     * @return uint8_t 视图（大小不变）
     */
    [[nodiscard]] inline auto as_u8(std::span<const std::byte> s) noexcept -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
    }

    /**
     * @brief std::string → uint8_t 只读视图
     * @param s 字符串
     * @return uint8_t 视图（size() 个元素）
     */
    [[nodiscard]] inline auto as_u8_span(const std::string &s) noexcept -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
    }

    /**
     * @brief std::string_view → uint8_t 只读视图
     * @param s 字符串视图
     * @return uint8_t 视图（size() 个元素）
     */
    [[nodiscard]] inline auto as_u8_span(std::string_view s) noexcept -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
    }

    /**
     * @brief 字符指针 + 长度 → uint8_t 只读视图
     * @param data 字符指针
     * @param len 元素数
     * @return uint8_t 视图
     */
    [[nodiscard]] inline auto as_u8_span(const char *data, std::size_t len) noexcept
        -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(data), len};
    }

    /**
     * @brief uint8_t 容器（vector/array）→ uint8_t 只读视图
     * @tparam C 满足 .data()/.size() 的容器
     * @param c 容器
     * @return uint8_t 视图
     */
    template <typename C>
        requires requires(const C &c) {
            { c.data() } -> std::same_as<const std::uint8_t *>;
            { c.size() } -> std::convertible_to<std::size_t>;
        }
    [[nodiscard]] inline auto as_u8_span(const C &c) noexcept -> std::span<const std::uint8_t>
    {
        return {c.data(), c.size()};
    }

    /**
     * @brief std::string → byte 只读视图
     * @param s 字符串
     * @return byte 视图（size() 个元素）
     */
    [[nodiscard]] inline auto as_bytes_span(const std::string &s) noexcept -> std::span<const std::byte>
    {
        return as_bytes(as_u8_span(s));
    }

    /**
     * @brief std::string_view → byte 只读视图
     * @param s 字符串视图
     * @return byte 视图（size() 个元素）
     */
    [[nodiscard]] inline auto as_bytes_span(std::string_view s) noexcept -> std::span<const std::byte>
    {
        return as_bytes(as_u8_span(s));
    }

    /**
     * @brief 字符指针 + 长度 → byte 只读视图
     * @param data 字符指针
     * @param len 元素数
     * @return byte 视图
     */
    [[nodiscard]] inline auto as_bytes_span(const char *data, std::size_t len) noexcept
        -> std::span<const std::byte>
    {
        return as_bytes(as_u8_span(data, len));
    }

    /**
     * @brief uint8_t 容器（vector/array）→ byte 只读视图
     * @tparam C 满足 .data()/.size() 的容器
     * @param c 容器
     * @return byte 视图
     */
    template <typename C>
        requires requires(const C &c) {
            { c.data() } -> std::same_as<const std::uint8_t *>;
            { c.size() } -> std::convertible_to<std::size_t>;
        }
    [[nodiscard]] inline auto as_bytes_span(const C &c) noexcept -> std::span<const std::byte>
    {
        return as_bytes(as_u8_span(c));
    }

    /**
     * @brief 字节只读视图 → std::string_view
     * @param s uint8_t 视图
     * @return string_view（size() 个字符）
     */
    [[nodiscard]] inline auto as_str_view(std::span<const std::uint8_t> s) noexcept -> std::string_view
    {
        return {reinterpret_cast<const char *>(s.data()), s.size()};
    }

    /**
     * @brief byte 只读视图 → std::string_view
     * @param s byte 视图
     * @return string_view（size() 个字符）
     */
    [[nodiscard]] inline auto as_str_view(std::span<const std::byte> s) noexcept -> std::string_view
    {
        return as_str_view(as_u8(s));
    }

} // namespace psmtest
