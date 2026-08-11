/**
 * @file client.hpp
 * @brief Shadowsocks 2022 客户端（握手编码）
 * @details 纯逻辑（无锁）：
 *          首包 = [salt 16][seal(固定头 11B)][seal(变长头)]
 *          变长头 = [ATYP][ADDR][PORT][padLen 2B][pad][payload]
 *          命名空间 psm_test::shadow2022，参考 mihomo shadowaead_2022/method.go。
 */

#pragma once

#include <common/common.hpp>
#include <common/mock/socks5.hpp>
#include <common/mock/shadowsocks2022/codec.hpp>

namespace psm_test::shadow2022
{

    using address = socks5::address;

    /**
     * @class client
     * @brief Shadowsocks 2022 客户端
     */
    class client
    {
    public:
        explicit client(const std::span<const std::uint8_t> psk)
        {
            std::copy(psk.begin(), psk.end(), psk_.begin());
        }

        /**
         * @brief 构造完整握手首包
         * @param dst 目标地址
         * @param payload 初始载荷（可选，写入变长头内）
         * @param time_sec UTC 秒
         * @return 首包字节
         */
        [[nodiscard]] auto handshake(const address &dst, const view payload,
                                     const std::uint64_t time_sec) -> buffer
        {
            // 变长头明文
            byte_writer var;
            encode_host(var, dst.type, dst.host);
            var.write_u16(dst.port);
            // padding（mihomo 客户端行为：载荷小时至少 1 字节随机填充，
            // sing-shadowsocks 服务端强制要求 padding 存在）
            const std::uint8_t pad_len = static_cast<std::uint8_t>(1 + std::rand() % 16);
            var.write_u16(pad_len);
            for (std::uint8_t i = 0; i < pad_len; ++i)
                var.write_u8(static_cast<std::uint8_t>(std::rand() & 0xFF));
            if (!payload.empty())
                var.write_bytes(payload);

            // 固定头明文
            const auto var_len = static_cast<std::uint16_t>(var.size());
            const auto fixed = build_fixed_header(header_type_client, time_sec, var_len);

            // 加密（同一会话密钥，nonce 从 0 递增）
            salt_ = rand16();
            const auto key = session_key(psk_, salt_);
            chunk_codec codec(key);
            const auto fixed_enc = codec.seal_raw(fixed);
            const auto var_enc = codec.seal_raw(var.data());

            byte_writer w;
            w.write_bytes(salt_);
            w.write_bytes(fixed_enc);
            w.write_bytes(var_enc);
            return w.data();
        }

        /// 上次握手使用的 salt（供响应解析派生密钥）
        [[nodiscard]] auto salt() const noexcept -> const std::array<std::uint8_t, key_len> &
        {
            return salt_;
        }

    private:
        [[nodiscard]] static auto rand16() -> std::array<std::uint8_t, key_len>
        {
            std::array<std::uint8_t, key_len> out{};
            for (auto &b : out)
                b = static_cast<std::uint8_t>(std::rand() & 0xFF);
            return out;
        }

        std::array<std::uint8_t, key_len> psk_{};
        std::array<std::uint8_t, key_len> salt_{};
    };

} // namespace psm_test::shadow2022
