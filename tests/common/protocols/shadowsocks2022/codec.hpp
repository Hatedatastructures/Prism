/**
 * @file codec.hpp
 * @brief SS2022 编解码（合并：头部编解码 + KDF + 分块 AEAD + 握手 + UDP 数据报）
 * @details 固定头/变长头明文编解码、地址编解码、BLAKE3 会话密钥派生、
 *          AEAD 分块编解码器（chunk_codec）、握手 serializer/parser、
 *          UDP 数据报逐包 AEAD 编解码（build_udp_packet /
 *          parse_udp_packet）全部集中于此。
 * @note 参考 SIP022 规范。
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <blake3.h>
#include <common/core/error.hpp>
#include <common/core/protocol/address.hpp>
#include <common/protocols/shadowsocks2022/types.hpp>

namespace preview::shadowsocks2022
{

    /**
     * @brief 构造固定头明文
     * @param type 头类型（0x00 请求 / 0x01 响应）
     * @param time_sec UTC 秒
     * @param var_len 变长头长度
     * @return 11 字节明文
     */
    [[nodiscard]] inline auto build_fixed_header(std::uint8_t type, std::uint64_t time_sec,
                                                 std::uint16_t var_len)
        -> std::array<std::uint8_t, fixed_hdr_plain>
    {
        std::array<std::uint8_t, fixed_hdr_plain> out{};
        out[0] = type;
        for (std::size_t i = 0; i < 8; ++i)
        {
            out[1 + i] = static_cast<std::uint8_t>((time_sec >> (56 - i * 8)) & 0xFF);
        }
        out[9] = static_cast<std::uint8_t>((var_len >> 8) & 0xFF);
        out[10] = static_cast<std::uint8_t>(var_len & 0xFF);
        return out;
    }

    /**
     * @brief 解析出的固定头字段
     */
    struct fixed_header
    {
        std::uint8_t type{0};      ///< 头类型
        std::uint64_t time_sec{0}; ///< UTC 秒
        std::uint16_t var_len{0};  ///< 变长头长度
    };

    /**
     * @brief 解析固定头明文
     * @param data 11 字节明文
     * @param out 输出固定头字段
     * @return 错误码
     */
    [[nodiscard]] inline auto parse_fixed_header(std::span<const std::uint8_t> data, fixed_header &out)
        -> error
    {
        if (data.size() < fixed_hdr_plain)
        {
            return error::need_more;
        }
        out.type = data[0];
        out.time_sec = 0;
        for (std::size_t i = 0; i < 8; ++i)
        {
            out.time_sec = (out.time_sec << 8) | data[1 + i];
        }
        out.var_len = static_cast<std::uint16_t>(data[9]) << 8 | data[10];
        return error::none;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param addr 目标地址
     * @param out 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 protocol/common::encode_address
     *       （原内联实现 ipv4 无校验存在越界写，统一实现修复为非法输入输出 0.0.0.0）
     */
    template <typename Alloc>
    inline auto encode_address(const address &addr, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        preview::protocol::common::encode_address(addr, out);
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     */
    [[nodiscard]] inline auto encode_address(const address &addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        encode_address(addr, out);
        return out;
    }

    /**
     * @brief 解析地址字节（ATYP + ADDR + PORT 2B BE）
     * @param data 完整缓冲区
     * @param addr 输出目标地址
     * @param off 输入起始偏移，输出结束偏移
     * @return 错误码
     */
    [[nodiscard]] inline auto parse_address(std::span<const std::uint8_t> data, address &addr,
                                            std::size_t &off) -> error
    {
        if (off >= data.size())
        {
            return error::need_more;
        }
        addr.type = static_cast<address_type>(data[off++]);
        switch (addr.type)
        {
        case address_type::ipv4: {
            if (data.size() < off + 4)
            {
                return error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", data[off], data[off + 1], data[off + 2],
                          data[off + 3]);
            addr.host = buf.data();
            off += 4;
            break;
        }
        case address_type::ipv6: {
            if (data.size() < off + 16)
            {
                return error::need_more;
            }
            addr.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
            off += 16;
            break;
        }
        case address_type::domain:
        default: {
            if (off >= data.size())
            {
                return error::need_more;
            }
            const auto len = data[off++];
            if (data.size() < off + len)
            {
                return error::need_more;
            }
            addr.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
            off += len;
            break;
        }
        }
        if (data.size() < off + 2)
        {
            return error::need_more;
        }
        addr.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        off += 2;
        return error::none;
    }

    /**
     * @brief 构造变长头明文（地址 + padding + 初始载荷）
     * @param addr 目标地址
     * @param pad_len padding 长度
     * @param payload 初始载荷（可空）
     * @return 变长头明文
     */
    [[nodiscard]] inline auto build_var_header(const address &addr, std::uint16_t pad_len,
                                               std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        auto out = encode_address(addr);
        out.push_back(static_cast<std::uint8_t>((pad_len >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(pad_len & 0xFF));
        for (std::uint16_t i = 0; i < pad_len; ++i)
        {
            out.push_back(0);
        }
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /**
     * @brief 解析变长头明文
     * @param data 变长头明文
     * @param addr 输出目标地址
     * @param payload 输出剩余载荷
     * @return 错误码
     */
    [[nodiscard]] inline auto parse_var_header(std::span<const std::uint8_t> data, address &addr,
                                               std::span<const std::uint8_t> &payload) -> error
    {
        if (data.size() < 2)
        {
            return error::need_more;
        }
        addr.type = static_cast<address_type>(data[0]);
        std::size_t off = 1;
        switch (addr.type)
        {
        case address_type::ipv4: {
            if (data.size() < off + 4)
            {
                return error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", data[off], data[off + 1], data[off + 2],
                          data[off + 3]);
            addr.host = buf.data();
            off += 4;
            break;
        }
        case address_type::ipv6: {
            if (data.size() < off + 16)
            {
                return error::need_more;
            }
            addr.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
            off += 16;
            break;
        }
        case address_type::domain:
        default: {
            if (off >= data.size())
            {
                return error::need_more;
            }
            const auto len = data[off++];
            if (data.size() < off + len)
            {
                return error::need_more;
            }
            addr.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
            off += len;
            break;
        }
        }
        if (data.size() < off + 2)
        {
            return error::need_more;
        }
        addr.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        off += 2;
        if (data.size() < off + 2)
        {
            return error::need_more;
        }
        const auto pad_len = static_cast<std::size_t>(data[off]) << 8 | data[off + 1];
        off += 2;
        if (data.size() < off + pad_len)
        {
            return error::need_more;
        }
        off += pad_len;
        payload = data.subspan(off);
        return error::none;
    }

    // ==================== chunk.hpp（分块 AEAD）合并 ====================

    namespace detail
    {

        /**
         * @brief nonce 小端 +1（对齐 Go increaseNonce）
         * @param nonce 12 字节 nonce（原地递增）
         */
        inline auto inc_nonce(std::span<std::uint8_t> nonce) -> void
        {
            for (auto &b : nonce)
            {
                ++b;
                if (b != 0)
                {
                    break;
                }
            }
        }

        /**
         * @brief AEAD 加密（AES-128-GCM，AAD 为空）
         * @param key 密钥
         * @param nonce12 12 字节 nonce
         * @param plain 明文
         * @return 密文 + tag
         */
        template <typename Alloc>
        [[nodiscard]] inline auto aead_seal(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> plain,
                                            std::vector<std::uint8_t, Alloc> &out) -> std::size_t
        {
            out.clear();
            out.resize(plain.size() + aead_tag_len);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return 0;
            }
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size()));
            int out_len = len;
            EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + out_len);
            out.resize(static_cast<std::size_t>(out_len) + aead_tag_len);
            EVP_CIPHER_CTX_free(ctx);
            return out.size();
        }

        /**
         * @brief AEAD 加密（写入 out 偏移处）
         * @param key 密钥
         * @param nonce12 12 字节 nonce
         * @param plain 明文
         * @param out 输出缓冲
         * @param offset 写入偏移（out 已预分配 offset + plain + tag）
         * @return 写入字节数（含 tag）；0 = 失败
         */
        template <typename Alloc>
        [[nodiscard]] inline auto aead_seal(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> plain,
                                            std::vector<std::uint8_t, Alloc> &out,
                                            const std::size_t offset) -> std::size_t
        {
            if (out.size() < offset + plain.size() + aead_tag_len)
            {
                out.resize(offset + plain.size() + aead_tag_len);
            }
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return 0;
            }
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_EncryptUpdate(ctx, out.data() + offset, &len, plain.data(), static_cast<int>(plain.size()));
            int out_len = len;
            EVP_EncryptFinal_ex(ctx, out.data() + offset + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + offset + out_len);
            EVP_CIPHER_CTX_free(ctx);
            return out_len + aead_tag_len;
        }

        [[nodiscard]] inline auto aead_seal(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> plain) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out;
            aead_seal(key, nonce12, plain, out);
            return out;
        }

        /**
         * @brief AEAD 解密（失败返回空）
         * @param key 密钥
         * @param nonce12 12 字节 nonce
         * @param cipher 密文（含 tag）
         * @return 明文；失败返回空
         */
        [[nodiscard]] inline auto aead_open(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> cipher) -> std::vector<std::uint8_t>
        {
            if (cipher.size() < aead_tag_len)
            {
                return {};
            }
            std::vector<std::uint8_t> out(cipher.size() - aead_tag_len);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(),
                              static_cast<int>(cipher.size() - aead_tag_len));
            int out_len = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(aead_tag_len),
                                const_cast<std::uint8_t *>(cipher.data()) + cipher.size() - aead_tag_len);
            const auto ok = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            if (ok != 1)
            {
                return {};
            }
            out.resize(static_cast<std::size_t>(out_len));
            return out;
        }

        /**
         * @brief 解密（写入复用缓冲）
         * @param key 密钥
         * @param nonce12 12 字节 nonce
         * @param cipher 密文（含 tag）
         * @param out 输出缓冲（调用方持有复用，热路径零分配）
         * @return true = 解密成功
         */
        template <typename Alloc>
        [[nodiscard]] inline auto aead_open(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> cipher,
                                            std::vector<std::uint8_t, Alloc> &out) -> bool
        {
            out.clear();
            if (cipher.size() < aead_tag_len)
            {
                return false;
            }
            out.resize(cipher.size() - aead_tag_len);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return false;
            }
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(),
                              static_cast<int>(cipher.size() - aead_tag_len));
            int out_len = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(aead_tag_len),
                                const_cast<std::uint8_t *>(cipher.data()) + cipher.size() - aead_tag_len);
            const auto ok = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            if (ok != 1)
            {
                out.clear();
                return false;
            }
            out.resize(static_cast<std::size_t>(out_len));
            return true;
        }

    } // namespace detail

    /**
     * @brief SS2022 AEAD 分块编解码器（状态机）
     */
    class chunk_codec
    {
    public:
        /**
         * @brief 构造
         * @param key 会话密钥（16 字节 aes-128-gcm）
         * @param start_nonce 起始 nonce（默认 0；握手消耗 2 个 nonce
         *                    后数据面从 2 开始，供互操作测试指定）
         */
        explicit chunk_codec(std::span<const std::uint8_t> key, std::size_t start_nonce = 0)
            : key_(key.begin(), key.end())
        {
            for (std::size_t i = 0; i < start_nonce; ++i)
            {
                detail::inc_nonce(nonce_);
            }
        }

        /**
         * @brief 加密单块（写入复用缓冲）
         * @param plain 明文
         * @param out 输出缓冲（调用方持有复用，热路径零分配）
         * @return 写入字节数；0 = 失败
         */
        template <typename Alloc>
        [[nodiscard]] auto seal(std::span<const std::uint8_t> plain,
                                std::vector<std::uint8_t, Alloc> &out) -> std::size_t
        {
            out.clear();
            std::array<std::uint8_t, 2> len_plain{static_cast<std::uint8_t>((plain.size() >> 8) & 0xFF),
                                                  static_cast<std::uint8_t>(plain.size() & 0xFF)};
            // 直接写 out：头 18B（len 密文）+ 尾部（body 密文），零中间分配
            const auto len_n = detail::aead_seal(key_, nonce_, len_plain, out);
            detail::inc_nonce(nonce_);
            out.resize(len_n + plain.size() + aead_tag_len);
            (void)detail::aead_seal(key_, nonce_, plain, out, len_n);
            detail::inc_nonce(nonce_);
            return out.size();
        }

        /**
         * @brief 加密单块（长度 nonce 递增）
         * @param plain 明文
         * @return [len 密文 18B][载荷密文 len+16B]
         */
        [[nodiscard]] auto seal(std::span<const std::uint8_t> plain) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out;
            seal(plain, out);
            return out;
        }

        /**
         * @brief 解密长度块（2 字节密文 + 16 tag）
         * @param head 18 字节长度块
         * @return 载荷长度（0 = 结束块）；nullopt = 校验失败
         */
        [[nodiscard]] auto open_len(std::span<const std::uint8_t> head) -> std::optional<std::size_t>
        {
            if (head.size() < len_block_size)
            {
                return std::nullopt;
            }
            const auto len_plain = detail::aead_open(key_, nonce_, head.first(len_block_size));
            if (len_plain.size() != 2)
            {
                return std::nullopt;
            }
            detail::inc_nonce(nonce_);
            const auto n = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];
            if (n > max_chunk_size)
            {
                return std::nullopt;
            }
            return n;
        }

        /**
         * @brief 解密载荷块（写入复用缓冲）
         * @param data 载荷密文块
         * @param out 输出缓冲（调用方持有复用，热路径零分配）
         * @return 明文长度；0 = 校验失败
         */
        template <typename Alloc>
        [[nodiscard]] auto open_payload(std::span<const std::uint8_t> data,
                                        std::vector<std::uint8_t, Alloc> &out) -> std::size_t
        {
            out.clear();
            if (data.size() < aead_tag_len)
            {
                return 0;
            }
            if (!detail::aead_open(key_, nonce_, data, out))
            {
                out.clear();
                return 0;
            }
            detail::inc_nonce(nonce_);
            return out.size();
        }

        /**
         * @brief 解密载荷块（n 字节密文 + 16 tag）
         * @param data 载荷密文块
         * @return 明文（空 = 校验失败）
         */
        [[nodiscard]] auto open_payload(std::span<const std::uint8_t> data) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out;
            open_payload(data, out);
            return out;
        }

        /**
         * @brief 解密单块（完整块：长度 + 载荷）
         * @param data 完整块
         * @param consumed 输出消耗字节数
         * @return 明文；空 = 失败或空块（len=0）
         */
        [[nodiscard]] auto open(std::span<const std::uint8_t> data, std::size_t &consumed)
            -> std::vector<std::uint8_t>
        {
            auto len = open_len(data);
            if (!len)
            {
                return {};
            }
            if (*len == 0)
            {
                consumed = len_block_size;
                return {};
            }
            if (data.size() < len_block_size + *len + aead_tag_len)
            {
                return {};
            }
            const auto body = open_payload(data.subspan(len_block_size, *len + aead_tag_len));
            if (body.empty())
            {
                return {};
            }
            consumed = len_block_size + *len + aead_tag_len;
            return body;
        }

        /**
         * @brief 加密裸块（无长度块，供 SS2022 握手头使用）
         * @param plain 明文
         * @return 密文（plain + 16B tag）；nonce 递增一次
         * @details 标准 SS2022 握手首部（请求/响应）为单个 AEAD 块，
         * 无长度块前缀；数据面才使用 chunk 流（seal/open）。
         */
        [[nodiscard]] auto seal_raw(std::span<const std::uint8_t> plain)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out;
            detail::aead_seal(key_, nonce_, plain, out);
            detail::inc_nonce(nonce_);
            return out;
        }

        /**
         * @brief 解密裸块（无长度块）
         * @param data 密文（plain + 16B tag）
         * @return 明文；空 = 校验失败
         * @details 与 seal_raw 配对，nonce 递增一次。
         */
        [[nodiscard]] auto open_raw(std::span<const std::uint8_t> data)
            -> std::vector<std::uint8_t>
        {
            auto out = detail::aead_open(key_, nonce_, data);
            if (out.empty())
            {
                return {};
            }
            detail::inc_nonce(nonce_);
            return out;
        }

        /**
         * @brief 解密裸块并返回认证结果（支持空明文）
         * @param data 密文（plain + 16B tag）
         * @param out 输出缓冲（调用方持有，可为空）
         * @return true = 认证通过且 nonce 推进；false = 校验失败
         * @details 与单参版本的区别：空明文（如响应 payloadLen=0
         * 的尾随空块）认证成功后同样推进 nonce，避免数据面失步。
         */
        template <typename Alloc>
        [[nodiscard]] auto open_raw(std::span<const std::uint8_t> data,
                                    std::vector<std::uint8_t, Alloc> &out) -> bool
        {
            if (!detail::aead_open(key_, nonce_, data, out))
            {
                return false;
            }
            detail::inc_nonce(nonce_);
            return true;
        }

        /**
         * @brief 结束块（长度 0）
         * @return 结束块密文
         */
        [[nodiscard]] auto finish() -> std::vector<std::uint8_t>
        {
            return seal({});
        }

    private:
        std::vector<std::uint8_t> key_;
        std::array<std::uint8_t, 12> nonce_{};
    };

    /**
     * @brief 派生会话密钥
     * @param psk 预共享密钥（16/32 字节）
     * @param salt 随机盐（与 psk 等长）
     * @param out_len 输出长度
     * @return 会话子密钥
     */
    [[nodiscard]] inline auto session_key(std::span<const std::uint8_t> psk,
                                          std::span<const std::uint8_t> salt, std::size_t out_len = 16)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> material;
        material.reserve(psk.size() + salt.size());
        material.insert(material.end(), psk.begin(), psk.end());
        material.insert(material.end(), salt.begin(), salt.end());
        std::vector<std::uint8_t> out(out_len);
        blake3_hasher hasher;
        blake3_hasher_init_derive_key(&hasher, kdf_context.data());
        blake3_hasher_update(&hasher, material.data(), material.size());
        blake3_hasher_finalize(&hasher, out.data(), out_len);
        return out;
    }

    // ==================== kdf.hpp（密钥派生）合并 ====================

    /**
     * @brief SS2022 握手消息（Beast 风格，供 serializer/parser 使用）
     */
    struct message
    {
        /// 目标地址
        address dst;
        /// 初始载荷（握手包内）
        std::string initial_payload;
    };

    /**
     * @brief SS2022 握手序列化器（对象 → wire，Beast 风格）
     */
    class serializer
    {
    public:
        /**
         * @brief 构造
         * @param psk 预共享密钥（16 字节）
         */
        explicit serializer(const std::array<std::uint8_t, 16> &psk) : psk_(psk)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param msg 消息
         * @param time_sec UTC 秒
         */
        auto reset(const message &msg, std::uint64_t time_sec) -> void
        {
            // @note 盐必须 CSPRNG：MinGW 的 std::random_device 存在确定性序列风险，
            //       盐重复 = 跨会话 keystream 重用（与生产 RAND_bytes 口径一致）
            std::array<std::uint8_t, 16> salt{};
            RAND_bytes(salt.data(), static_cast<int>(salt.size()));
            const auto key = session_key(psk_, salt, 16);

            std::random_device rd; // padding 长度非密码学用途，random_device 足够
            const auto pad_len = static_cast<std::uint16_t>(1 + rd() % 16);
            std::vector<std::uint8_t> var;
            const auto addr = encode_address(msg.dst);
            var.insert(var.end(), addr.begin(), addr.end());
            var.push_back(static_cast<std::uint8_t>((pad_len >> 8) & 0xFF));
            var.push_back(static_cast<std::uint8_t>(pad_len & 0xFF));
            for (std::uint16_t i = 0; i < pad_len; ++i)
            {
                var.push_back(static_cast<std::uint8_t>(rd() & 0xFF));
            }
            var.insert(var.end(), msg.initial_payload.begin(), msg.initial_payload.end());

            const auto fixed =
                build_fixed_header(header_type_client, time_sec, static_cast<std::uint16_t>(var.size()));

            chunk_codec codec(key);
            const auto fixed_enc = codec.seal_raw(fixed);
            const auto var_enc = codec.seal_raw(var);

            wire_.clear();
            wire_.reserve(salt.size() + fixed_enc.size() + var_enc.size());
            wire_.insert(wire_.end(), salt.begin(), salt.end());
            wire_.insert(wire_.end(), fixed_enc.begin(), fixed_enc.end());
            wire_.insert(wire_.end(), var_enc.begin(), var_enc.end());
            offset_ = 0;
        }

        /**
         * @brief 增量输出
         */
        auto get(boost::asio::mutable_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto n = std::min(buffer.size(), wire_.size() - offset_);
            std::memcpy(buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto is_done() const -> bool
        {
            return offset_ >= wire_.size();
        }

    private:
        std::array<std::uint8_t, 16> psk_;
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /**
     * @brief SS2022 握手解析器（wire → 对象，Beast 风格）
     */
    class parser
    {
    public:
        /**
         * @brief 构造
         * @param psk 预共享密钥（16 字节）
         */
        explicit parser(const std::array<std::uint8_t, 16> &psk) : psk_(psk)
        {
        }

        /**
         * @brief 增量喂入
         */
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(buffer.data()),
                                                            buffer.size());
            buf_.insert(buf_.end(), data.begin(), data.end());
            if (buf_.size() < 16 + fixed_hdr_plain + aead_tag_len)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }

            const auto salt = std::span<const std::uint8_t>(buf_).first(16);
            const auto key = session_key(psk_, salt, 16);
            chunk_codec codec(key);

            auto fixed_plain = codec.open_raw(std::span<const std::uint8_t>(buf_).subspan(
                                                  16, fixed_hdr_plain + aead_tag_len));
            if (fixed_plain.size() != fixed_hdr_plain || fixed_plain[0] != header_type_client)
            {
                ec = make_error_code(error::auth_failed);
                return 0;
            }
            const auto var_len = static_cast<std::size_t>(fixed_plain[9]) << 8 | fixed_plain[10];
            if (buf_.size() < 16 + fixed_hdr_plain + aead_tag_len + var_len + aead_tag_len)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }
            auto var_plain = codec.open_raw(std::span<const std::uint8_t>(buf_).subspan(
                                                16 + fixed_hdr_plain + aead_tag_len,
                                                var_len + aead_tag_len));
            if (var_plain.empty())
            {
                ec = make_error_code(error::auth_failed);
                return 0;
            }

            std::size_t off = 0;
            auto err = parse_address(std::span<const std::uint8_t>(var_plain).subspan(off), msg_.dst, off);
            if (err != error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            if (var_plain.size() < off + 2)
            {
                ec = make_error_code(error::bad_message);
                return 0;
            }
            const auto pad_len = static_cast<std::size_t>(var_plain[off]) << 8 | var_plain[off + 1];
            off += 2;
            if (var_plain.size() < off + pad_len)
            {
                ec = make_error_code(error::bad_message);
                return 0;
            }
            off += pad_len;
            msg_.initial_payload.assign(reinterpret_cast<const char *>(var_plain.data() + off),
                                        var_plain.size() - off);
            done_ = true;
            return buf_.size();
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto is_done() const -> bool
        {
            return done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto get() const -> const message &
        {
            return msg_;
        }

        /**
         * @brief 重置
         */
        auto reset() -> void
        {
            buf_.clear();
            msg_ = message{};
            done_ = false;
        }

    private:
        std::array<std::uint8_t, 16> psk_;
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool done_{false};
    };

    // ==================== datagram.hpp（UDP 数据报编解码）合并 ====================

    /// UDP 数据报类型字节（简化变体固定 0x01）
    inline constexpr std::uint8_t udp_type = 0x01;

    /// SessionID 长度（SeparateHeader 前 8 字节）
    inline constexpr std::size_t session_id_len = 8;

    /// PacketID 长度（SeparateHeader 后 8 字节）
    inline constexpr std::size_t packet_id_len = 8;

    /// SeparateHeader 总长度（SessionID + PacketID）
    inline constexpr std::size_t separate_hdr_len = session_id_len + packet_id_len;

    /// 时间戳长度（8 字节大端）
    inline constexpr std::size_t udp_ts_len = 8;

    /// 单个 UDP 数据报载荷上限（测试库约定）
    inline constexpr std::size_t max_udp_payload = 65535;

    namespace detail
    {

        /**
         * @brief UDP 数据报 AEAD 加密输入
         */
        struct udp_seal_input
        {
            std::span<const std::uint8_t> key;   ///< 16 字节会话密钥
            std::span<const std::uint8_t> nonce; ///< 12 字节 nonce
            std::span<const std::uint8_t> plain; ///< 明文载荷
            std::span<const std::uint8_t> aad;   ///< 附加认证数据
        };

        /**
         * @brief UDP 数据报 AEAD 解密输入
         */
        struct udp_open_input
        {
            std::span<const std::uint8_t> key;    ///< 16 字节会话密钥
            std::span<const std::uint8_t> nonce;  ///< 12 字节 nonce
            std::span<const std::uint8_t> cipher; ///< 密文 + 16B tag
            std::span<const std::uint8_t> aad;    ///< 附加认证数据
        };

        /**
         * @brief UDP 数据报单次 AES-128-GCM 加密（带 AAD）
         * @param in 加密输入
         * @return 密文 + 16B tag；失败返回空
         * @details 与 chunk_codec 的 AEAD 等价，仅多出 AAD 参数。
         */
        [[nodiscard]] inline auto udp_seal(const udp_seal_input &in) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out(in.plain.size() + aead_tag_len);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.nonce.data());
            if (!in.aad.empty())
            {
                EVP_EncryptUpdate(ctx, nullptr, &len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_EncryptUpdate(ctx, out.data(), &len, in.plain.data(), static_cast<int>(in.plain.size()));
            int out_len = len;
            EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + out_len);
            out.resize(static_cast<std::size_t>(out_len) + aead_tag_len);
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        /**
         * @brief UDP 数据报单次 AES-128-GCM 解密（带 AAD）
         * @param in 解密输入
         * @return 明文；空 = 校验失败或空载荷
         * @details tag 校验失败返回空，调用方需结合 cipher 长度区分
         * 空载荷与失败（约定：cipher 恰为 16B tag 时空返回合法）。
         */
        [[nodiscard]] inline auto udp_open(const udp_open_input &in) -> std::vector<std::uint8_t>
        {
            if (in.cipher.size() < aead_tag_len)
            {
                return {};
            }
            std::vector<std::uint8_t> out(in.cipher.size() - aead_tag_len);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.nonce.data());
            if (!in.aad.empty())
            {
                EVP_DecryptUpdate(ctx, nullptr, &len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_DecryptUpdate(ctx, out.data(), &len, in.cipher.data(),
                              static_cast<int>(in.cipher.size() - aead_tag_len));
            int out_len = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(aead_tag_len),
                                const_cast<std::uint8_t *>(in.cipher.data()) + in.cipher.size() -
                                    aead_tag_len);
            const auto ok = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            if (ok != 1)
            {
                return {};
            }
            out.resize(static_cast<std::size_t>(out_len));
            return out;
        }

    } // namespace detail

    /**
     * @brief UDP 数据报构造输入
     */
    struct udp_build_input
    {
        std::span<const std::uint8_t> session_key; ///< 16 字节会话密钥
        std::uint64_t packet_id{0};                ///< 递增包序号
        const address *target{nullptr};            ///< 目标地址
        std::span<const std::uint8_t> payload;     ///< 载荷明文
    };

    /**
     * @brief UDP 数据报解析输入
     */
    struct udp_parse_input
    {
        std::span<const std::uint8_t> session_key;   ///< 16 字节会话密钥
        std::span<const std::uint8_t> packet;        ///< 完整数据报
        address *target{nullptr};                    ///< 输出目标地址
        std::vector<std::uint8_t> *payload{nullptr}; ///< 输出载荷
    };

    /**
     * @brief 构造 UDP 数据报（写入复用缓冲）
     * @param in 构造输入
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     * @return false = 参数非法
     */
    template <typename Alloc>
    [[nodiscard]] inline auto build_udp_packet(const udp_build_input &in,
                                               std::vector<std::uint8_t, Alloc> &out) -> bool
    {
        out.clear();
        if (!in.target || in.session_key.size() < session_id_len + packet_id_len)
        {
            return false;
        }

        // 1. SeparateHeader（明文）：SessionID(8) + PacketID(8 BE)
        std::array<std::uint8_t, separate_hdr_len> separate{};
        std::memcpy(separate.data(), in.session_key.data(), session_id_len);
        for (std::size_t i = 0; i < packet_id_len; ++i)
        {
            separate[session_id_len + i] = static_cast<std::uint8_t>((in.packet_id >> (56 - i * 8)) & 0xFF);
        }

        // 2. 明文头部：Type(1) + Timestamp(8 BE) + 地址（ATYP + ADDR + PORT 2B）
        std::vector<std::uint8_t> head;
        head.reserve(1 + udp_ts_len + 24);
        head.push_back(udp_type);
        const auto ts = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                                       std::chrono::system_clock::now().time_since_epoch())
                                                       .count());
        for (std::size_t i = 0; i < udp_ts_len; ++i)
        {
            head.push_back(static_cast<std::uint8_t>((ts >> (56 - i * 8)) & 0xFF));
        }
        encode_address(*in.target, head);

        // 3. nonce = SessionID[4..8] + PacketID[0..8]（12 字节）
        std::array<std::uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), separate.data() + session_id_len / 2, session_id_len / 2);
        std::memcpy(nonce.data() + session_id_len / 2, separate.data() + session_id_len, packet_id_len);

        // 4. 加密载荷（AAD = SeparateHeader）并组装
        const auto body_enc =
            detail::udp_seal(detail::udp_seal_input{in.session_key, nonce, in.payload, separate});
        if (body_enc.empty())
        {
            return false;
        }
        out.reserve(separate.size() + head.size() + body_enc.size());
        out.insert(out.end(), separate.begin(), separate.end());
        out.insert(out.end(), head.begin(), head.end());
        out.insert(out.end(), body_enc.begin(), body_enc.end());
        return true;
    }

    /**
     * @brief 构造 UDP 数据报（逐包 AEAD 无状态加密）
     * @param in 构造输入
     * @return 完整数据报字节；参数非法返回空
     * @details 格式见文件头注释。与 parse_udp_packet 配对使用，
     * 不依赖任何会话状态，可用任意递增 packet_id 序列。
     */
    [[nodiscard]] inline auto build_udp_packet(const udp_build_input &in) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        build_udp_packet(in, out);
        return out;
    }

    /**
     * @brief 解析 UDP 数据报（逐包 AEAD 无状态解密）
     * @param in 解析输入（session_key + packet + 输出 target/payload）
     * @return 错误码；bad_auth = SessionID 不匹配 / tag 校验失败，
     *         bad_message = 类型字节非法
     * @details 与 build_udp_packet 配对使用。只解析 Type + 地址 +
     * 载荷；时间戳不校验（简化变体）。
     */
    [[nodiscard]] inline auto parse_udp_packet(const udp_parse_input &in) -> error
    {
        if (!in.target || !in.payload)
        {
            return error::bad_length;
        }
        const auto &session_key16 = in.session_key;
        const auto &packet = in.packet;
        auto &target = *in.target;
        auto &payload = *in.payload;
        // 最小长度：SeparateHeader(16) + Type(1) + TS(8) + ATYP(1) + PORT(2) + tag(16)
        if (session_key16.size() < session_id_len ||
            packet.size() < separate_hdr_len + 1 + udp_ts_len + 1 + 2 + aead_tag_len)
        {
            return error::bad_length;
        }
        const auto separate = packet.first(separate_hdr_len);

        // SessionID 校验（前 8 字节须与会话密钥一致）
        if (std::memcmp(separate.data(), session_key16.data(), session_id_len) != 0)
        {
            return error::bad_auth;
        }

        // 类型字节校验
        if (packet[separate_hdr_len] != udp_type)
        {
            return error::bad_message;
        }

        // 解析明文头部中的目标地址（ATYP + ADDR + PORT 2B BE）
        std::size_t off = separate_hdr_len + 1 + udp_ts_len;
        std::size_t consumed = 0;
        auto err = parse_address(packet.subspan(off), target, consumed);
        if (err != error::none)
        {
            return err;
        }
        off += consumed;

        // nonce = SessionID[4..8] + PacketID[0..8]（12 字节）
        std::array<std::uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), separate.data() + session_id_len / 2, session_id_len / 2);
        std::memcpy(nonce.data() + session_id_len / 2, separate.data() + session_id_len, packet_id_len);

        // 解密载荷（AAD = SeparateHeader）；cipher 恰为 tag 时允许空载荷
        const auto body_enc = packet.subspan(off);
        const auto body = detail::udp_open(detail::udp_open_input{session_key16, nonce, body_enc, separate});
        if (body.empty() && body_enc.size() > aead_tag_len)
        {
            return error::bad_auth;
        }
        payload = body;
        return error::none;
    }

} // namespace preview::shadowsocks2022
