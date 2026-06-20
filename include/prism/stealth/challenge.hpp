/**
 * @file challenge.hpp
 * @brief 挑战-响应令牌(RFC-065 Phase 3)
 * @details 使用 BLAKE3 keyed_hash 生成 16 字节挑战令牌。
 *          服务端在探测防御触发时嵌入挑战,合法客户端返回响应。
 */

#pragma once

#include <prism/core/fault/code.hpp>
#include <prism/core/memory/container.hpp>
#include <prism/stealth/tracker.hpp>

#include <array>
#include <cstdint>
#include <span>


namespace psm::stealth
{

    /**
     * @brief 挑战令牌(16 字节,BLAKE3 keyed_hash 截断)
     */
    struct challenge_token
    {
        std::array<std::byte, 16> bytes{};

        [[nodiscard]] auto operator==(const challenge_token &) const noexcept -> bool = default;
    };

    /**
     * @brief 挑战-响应验证结果
     */
    struct challenge_result
    {
        bool triggered{false};
        bool success{false};
        fault::code error{fault::code::success};
    };

    /**
     * @brief 生成挑战令牌的输入参数(Rule 1: ≤3 参数收敛)
     */
    struct challenge_input
    {
        const address_hash &src;
        std::span<const std::uint8_t> sni;
        std::uint64_t counter{0};
        std::array<std::uint8_t, 32> server_secret{};
    };

    /**
     * @brief 生成挑战令牌(纯函数)
     * @details BLAKE3 keyed_hash(secret, src || sni || counter),截断 16 字节。
     *          按字段依次 update,消除编码歧义。
     */
    [[nodiscard]] auto generate_challenge(const challenge_input &input) noexcept -> challenge_token;

    /**
     * @brief 验证挑战响应(纯函数)
     */
    [[nodiscard]] auto verify_challenge(
        const challenge_token &expected,
        std::span<const std::byte> response) noexcept -> bool;

} // namespace psm::stealth
