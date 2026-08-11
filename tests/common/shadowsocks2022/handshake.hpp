/**
 * @file handshake.hpp
 * @brief SS2022 握手消息序列化器 / 解析器类（Beast 风格）
 * @details serializer：message + 时间戳 → 完整握手包
 *          （salt + 固定头密文 + 变长头密文）；
 *          parser：握手包 → message（地址 + 初始载荷），
 *          错误 PSK 返回 auth_failed。
 * @note 参考 SIP022 规范。
 */

#pragma once

#include <common/shadowsocks2022/chunk.hpp>
#include <common/shadowsocks2022/codec.hpp>
#include <common/shadowsocks2022/kdf.hpp>
#include <common/shadowsocks2022/types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace psmtest::ss2022
{

    /// @brief SS2022 握手消息（Beast 风格，供 serializer/parser 使用）
    struct message
    {
        /// 目标地址
        address dst;
        /// 初始载荷（握手包内）
        std::string initial_payload;
    };

    /// @brief SS2022 握手序列化器（对象 → wire，Beast 风格）
    class serializer
    {
    public:
        /// @brief 构造
        /// @param psk 预共享密钥（16 字节）
        explicit serializer(const std::array<std::uint8_t, 16> &psk)
            : psk_(psk)
        {
        }

        /// @brief 重置并绑定消息
        /// @param msg 消息
        /// @param time_sec UTC 秒
        auto reset(const message &msg, std::uint64_t time_sec) -> void
        {
            std::random_device rd;
            std::array<std::uint8_t, 16> salt{};
            for (auto &b : salt)
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            const auto key = session_key(psk_, salt, 16);

            const auto pad_len = static_cast<std::uint16_t>(1 + rd() % 16);
            std::vector<std::uint8_t> var;
            const auto addr = encode_address(msg.dst);
            var.insert(var.end(), addr.begin(), addr.end());
            var.push_back(static_cast<std::uint8_t>((pad_len >> 8) & 0xFF));
            var.push_back(static_cast<std::uint8_t>(pad_len & 0xFF));
            for (std::uint16_t i = 0; i < pad_len; ++i)
                var.push_back(static_cast<std::uint8_t>(rd() & 0xFF));
            var.insert(var.end(), msg.initial_payload.begin(), msg.initial_payload.end());

            const auto fixed = build_fixed_header(header_type_client, time_sec,
                                                  static_cast<std::uint16_t>(var.size()));

            chunk_codec codec(key);
            const auto fixed_enc = codec.seal(fixed);
            const auto var_enc = codec.seal(var);

            wire_.clear();
            wire_.reserve(salt.size() + fixed_enc.size() + var_enc.size());
            wire_.insert(wire_.end(), salt.begin(), salt.end());
            wire_.insert(wire_.end(), fixed_enc.begin(), fixed_enc.end());
            wire_.insert(wire_.end(), var_enc.begin(), var_enc.end());
            offset_ = 0;
        }

        /// @brief 增量输出
        auto get(boost::asio::mutable_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto n = std::min(buffer.size(), wire_.size() - offset_);
            std::memcpy(buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /// 是否已全部输出
        [[nodiscard]] auto is_done() const -> bool
        {
            return offset_ >= wire_.size();
        }

    private:
        std::array<std::uint8_t, 16> psk_;
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /// @brief SS2022 握手解析器（wire → 对象，Beast 风格）
    class parser
    {
    public:
        /// @brief 构造
        /// @param psk 预共享密钥（16 字节）
        explicit parser(const std::array<std::uint8_t, 16> &psk)
            : psk_(psk)
        {
        }

        /// @brief 增量喂入
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(buffer.data()), buffer.size());
            buf_.insert(buf_.end(), data.begin(), data.end());
            if (buf_.size() < 16 + len_block_size + fixed_hdr_plain + aead_tag_len)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }

            const auto salt = std::span<const std::uint8_t>(buf_).first(16);
            const auto key = session_key(psk_, salt, 16);
            chunk_codec codec(key);

            std::size_t consumed = 0;
            auto fixed_plain = codec.open(
                std::span<const std::uint8_t>(buf_).subspan(
                    16, len_block_size + fixed_hdr_plain + aead_tag_len),
                consumed);
            if (fixed_plain.size() != fixed_hdr_plain || fixed_plain[0] != header_type_client)
            {
                ec = make_error_code(error::auth_failed);
                return 0;
            }
            const auto var_len = static_cast<std::size_t>(fixed_plain[9]) << 8 | fixed_plain[10];
            if (buf_.size() < 16 + len_block_size + fixed_hdr_plain + aead_tag_len +
                                  len_block_size + var_len + aead_tag_len)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }
            auto var_plain = codec.open(
                std::span<const std::uint8_t>(buf_).subspan(
                    16 + len_block_size + fixed_hdr_plain + aead_tag_len,
                    len_block_size + var_len + aead_tag_len),
                consumed);
            if (var_plain.empty())
            {
                ec = make_error_code(error::auth_failed);
                return 0;
            }

            std::size_t off = 0;
            auto err = parse_address(std::span<const std::uint8_t>(var_plain).subspan(off),
                                     msg_.dst, off);
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
            msg_.initial_payload.assign(
                reinterpret_cast<const char *>(var_plain.data() + off), var_plain.size() - off);
            done_ = true;
            return buf_.size();
        }

        /// 是否解析完成
        [[nodiscard]] auto is_done() const -> bool
        {
            return done_;
        }

        /// 解析结果
        [[nodiscard]] auto get() const -> const message &
        {
            return msg_;
        }

        /// 重置
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

} // namespace psmtest::ss2022
