/**
 * @file AuthHeader.hpp
 * @brief VMess AEAD 认证头密封与打开
 * @details 负责认证头的随机 nonce、长度块和请求头载荷的 wire 编排。
 *          AuthID、UUID/cmdKey 和 KDF 分别由 AuthId.hpp、AuthKdf.hpp 提供。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>

namespace Prism::Vmess
{

    using RandomSource = std::function<int(std::uint8_t *, int)>;

    /**
     * @brief 认证头密封输入
     */
    struct AuthHeaderInput
    {
        std::span<const std::uint8_t> Body;
        std::int64_t TimeSec{0};
        std::span<const std::uint8_t, 4> random;
    };

    /**
     * @brief 密封 AEAD 认证头
     * @param CmdKey 16 字节 cmdKey
     * @param Input 输入（body + TimeSec + random）
     * @param Source 可选随机源
     * @return 认证头字节
     */
    [[nodiscard]] auto SealAuthHeader(
        std::span<const std::uint8_t, 16> CmdKey,
        const AuthHeaderInput &Input,
        const RandomSource &Source) -> std::vector<std::uint8_t>;

    [[nodiscard]] auto SealAuthHeader(
        std::span<const std::uint8_t, 16> CmdKey,
        const AuthHeaderInput &Input) -> std::vector<std::uint8_t>;

    /**
     * @brief 打开 AEAD 认证头
     * @param CmdKey 16 字节 cmdKey
     * @param Header 认证头
     * @param Output 输出明文载荷
     * @return 错误码
     */
    [[nodiscard]] auto OpenAuthHeader(
        std::span<const std::uint8_t, 16> CmdKey,
        std::span<const std::uint8_t> Header,
        std::vector<std::uint8_t> &Output) -> Error;

} // namespace Prism::Vmess
