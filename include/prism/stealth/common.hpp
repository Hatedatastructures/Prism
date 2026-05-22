/**
 * @file common.hpp
 * @brief 伪装层共享工具函数
 * @details 提供 AEAD nonce 构造、TLS 记录附加数据生成、异或运算、
 *          原始 TLS 帧读取等共享基础设施，供 reality/shadowtls/restls 等伪装方案复用。
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

#include <boost/asio.hpp>

#include <prism/memory/container.hpp>
#include <prism/protocol/tls/types.hpp>

namespace net = boost::asio;

namespace psm::stealth::common
{

    /**
     * @brief 构造 AEAD nonce
     * @details 将 12 字节 IV 与 64 位序列号按 TLS 1.3 规范异或，生成每记录唯一 nonce。
     * @param iv 12 字节初始化向量
     * @param sequence 记录序列号
     * @return 12 字节 nonce
     */
    [[nodiscard]] inline auto make_aead_nonce(
        std::span<const std::uint8_t> iv,
        std::uint64_t sequence) noexcept
        -> std::array<std::uint8_t, 12>
    {
        std::array<std::uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), iv.data(), 12);
        for (int i = 0; i < 8; ++i)
        {
            nonce[12 - 1 - i] ^= static_cast<std::uint8_t>((sequence >> (8 * i)) & 0xFF);
        }
        return nonce;
    }

    /**
     * @brief 构造 TLS 记录附加数据 (AEAD AAD)
     * @details 生成 5 字节 TLS 记录头作为 AEAD 加密的附加数据，
     *          内容类型为 Application Data (0x17)，版本号为 TLS 1.2 (0x0303)。
     * @param encrypted_len 加密后载荷长度
     * @return 5 字节附加数据
     */
    [[nodiscard]] inline auto make_record_ad(std::uint16_t encrypted_len) noexcept
        -> std::array<std::uint8_t, 5>
    {
        return {{0x17,       // CONTENT_TYPE_APPLICATION_DATA
                 0x03, 0x03, // TLS 1.2 version
                 static_cast<std::uint8_t>((encrypted_len >> 8) & 0xFF),
                 static_cast<std::uint8_t>(encrypted_len & 0xFF)}};
    }

    /**
     * @brief 用密钥对数据执行循环异或
     * @details 将 data 与 key 循环异或，用于 ShadowTLS 等方案的载荷混淆。
     * @param data 待异或的数据（就地修改）
     * @param key 异或密钥
     */
    inline void xor_with_key(std::span<std::byte> data, std::span<const std::uint8_t> key) noexcept
    {
        for (std::size_t i = 0; i < data.size(); ++i)
        {
            data[i] = static_cast<std::byte>(
                static_cast<std::uint8_t>(data[i]) ^ key[i % key.size()]);
        }
    }

    /**
     * @brief 从 TCP socket 读取一帧完整的原始 TLS 记录
     * @details 先读取 5 字节 TLS 记录头解析载荷长度，再读取完整载荷，
     *          返回包含记录头 + 载荷的完整帧。
     * @param sock TCP socket
     * @param ec 错误码输出参数
     * @return 完整 TLS 帧数据，读取失败时返回 std::nullopt
     */
    auto read_raw_tls_frame(net::ip::tcp::socket &sock, std::error_code &ec)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>;

} // namespace psm::stealth::common
