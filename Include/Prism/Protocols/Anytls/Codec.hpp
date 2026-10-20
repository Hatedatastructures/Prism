/**
 * @file Codec.hpp
 * @brief AnyTLS 认证帧编解码（纯函数）
 * @details 对齐 mihomo transport/anytls/Client.go 与
 * Prism AnyTLS 认证帧契约：
 *          认证帧 = [SHA-256(password) 32B][PadLen 2B BE][Padding]
 * @note 参考 AnyTLS 协议规范。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <Prism/Foundation/Error.hpp>

namespace Prism::Anytls
{

    /// 认证密码哈希长度（SHA-256）。
    inline constexpr std::size_t PasswordHashLen = 32;

    /// 认证帧 Padding 长度字段大小（2 字节大端）。
    inline constexpr std::size_t PadLenFieldSize = 2;

    /// 认证帧固定开销（Hash 32 + padlen 2）。
    inline constexpr std::size_t AuthFrameHdrlen = PasswordHashLen + PadLenFieldSize;

    /**
     * @brief 计算密码哈希
     * @param Password 密码
     * @return SHA-256(password) 32 字节
     */
    [[nodiscard]] auto PasswordHash(std::string_view Password)
        -> std::array<std::uint8_t, PasswordHashLen>;

    /**
     * @brief 构造认证帧
     * @param Password 密码
     * @param PadLen Padding 长度
     * @param Output 输出帧 [Hash 32][PadLen 2 BE][Padding]
     * @return 错误码
     */
    [[nodiscard]] auto BuildAuthFrame(
        std::string_view Password,
        std::uint16_t PadLen,
        std::string &Output) -> Error;

    /**
     * @brief 解析认证帧
     * @param Data 帧数据
     * @param Hash 输出密码哈希（32 字节）
     * @param PadLen 输出 Padding 长度
     * @return 错误码；bad_length = 帧过短
     */
    [[nodiscard]] auto ParseAuthFrame(
        std::span<const std::uint8_t> Data,
        std::array<std::uint8_t, PasswordHashLen> &Hash,
        std::uint16_t &PadLen) -> Error;

    /**
     * @brief 校验认证帧密码
     * @param Password 期望密码
     * @param Hash 帧内密码哈希
     * @return true = 匹配
     */
    [[nodiscard]] auto VerifyAuth(
        std::string_view Password,
        const std::array<std::uint8_t, PasswordHashLen> &Hash) -> bool;

} // namespace Prism::Anytls
