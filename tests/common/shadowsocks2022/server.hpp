/**
 * @file server.hpp
 * @brief Shadowsocks 2022 服务端（握手解析 + 响应）
 * @details 纯逻辑（无锁）：
 *          解析 = [salt 16][open(固定头)][open(变长头)]
 *          响应 = [serverSalt 16][seal(固定头 27B)][seal(空块)]
 *          命名空间 psm_test::shadow2022，参考 mihomo shadowaead_2022/method.go。
 */

#pragma once

#include <common/common.hpp>
#include <common/socks5/socks5.hpp>
#include <common/shadowsocks2022/codec.hpp>

namespace psm_test::shadow2022
{

    using address = socks5::address;

    /**
     * @class server
     * @brief Shadowsocks 2022 服务端
     */
    class server
    {
    public:
        explicit server(const std::span<const std::uint8_t> psk)
        {
            std::copy(psk.begin(), psk.end(), psk_.begin());
        }

        /// 解析结果
        struct request
        {
            address dst;
            buffer initial_payload;
            bool valid{false};
        };

        /**
         * @brief 解析握手首包
         * @param data 完整首包（>= 16 + 27 + 16）
         * @param time_sec 当前 UTC 秒（时间窗口校验）
         * @param window 时间窗口（秒）
         */
        [[nodiscard]] auto parse(const view data, const std::uint64_t time_sec,
                                 const std::uint64_t window = 90) -> request
        {
            request req;
            if (data.size() < 16 + 27 + 16)
                return req;
            const view salt(data.data(), key_len);
            const view fixed_enc(data.data() + key_len, fixed_header_len + aead_tag_len);
            const view var_enc(data.data() + key_len + fixed_header_len + aead_tag_len, data.size() - key_len - fixed_header_len - aead_tag_len);

            const auto key = session_key(psk_, salt);
            chunk_codec codec(key);

            const auto fixed = codec.open_raw(fixed_enc, fixed_buf_);
            if (!fixed || fixed_buf_.size() != fixed_header_len)
                return req;
            if (fixed_buf_[0] != header_type_client)
                return req;

            // 时间戳窗口
            std::uint64_t ts = 0;
            for (std::size_t i = 0; i < 8; ++i)
                ts = (ts << 8) | fixed_buf_[1 + i];
            const auto diff = time_sec > ts ? time_sec - ts : ts - time_sec;
            if (diff > window)
                return req;

            // 变长头
            const auto var_len = static_cast<std::size_t>(
                (fixed_buf_[9] << 8) | fixed_buf_[10]);
            if (var_enc.size() < var_len + aead_tag_len)
                return req;
            if (!codec.open_raw(var_enc, var_buf_))
                return req;

            byte_reader r(var_buf_);
            if (!parse_host(r, req.dst.type, req.dst.host))
                return req;
            if (!r.read_u16(req.dst.port))
                return req;
            std::uint16_t pad_len = 0;
            if (!r.read_u16(pad_len))
                return req;
            if (!r.skip(pad_len))
                return req;
            req.initial_payload.assign(var_buf_.begin() + static_cast<std::ptrdiff_t>(r.offset()),
                                       var_buf_.end());
            req.valid = true;
            return req;
        }

        /**
         * @brief 构造服务端响应（mihomo 兼容）
         * @param client_salt 客户端 salt（写入响应固定头 requestSalt 字段）
         * @param server_time 服务端时间戳
         * @param server_salt 输出服务端 salt（随机）
         * @return 响应字节：[serverSalt 16][seal(固定头 27B) 43B][seal(空块) 16B]
         */
        [[nodiscard]] auto respond(const view client_salt, const std::uint64_t server_time,
                                   std::array<std::uint8_t, key_len> &server_salt) -> buffer
        {
            for (auto &b : server_salt)
                b = static_cast<std::uint8_t>(std::rand() & 0xFF);

            // 响应固定头明文 27 字节：type + ts + requestSalt 16 + paddingLen 2
            std::array<std::uint8_t, 1 + 8 + key_len + 2> plain{};
            plain[0] = header_type_server;
            for (std::size_t i = 0; i < 8; ++i)
                plain[1 + i] = static_cast<std::uint8_t>(server_time >> (56 - 8 * i));
            std::copy(client_salt.begin(), client_salt.end(), plain.begin() + 9);
            plain[9 + key_len] = 0;
            plain[9 + key_len + 1] = 0;

            const auto key = session_key(psk_, server_salt);
            chunk_codec codec(key);
            const auto fixed_enc = codec.seal_raw(plain);
            // 空块：v0.2.12 客户端 readResponse 在 payloadLen=0 时仍直读 16B（ReadWithLength(0)）
            const auto empty_enc = codec.seal_raw({});

            byte_writer w;
            w.write_bytes(server_salt);
            w.write_bytes(fixed_enc);
            w.write_bytes(empty_enc);
            return w.data();
        }

        /// 校验服务端响应（客户端侧，mihomo 服务端兼容）：
        /// [serverSalt 16][open(固定头 43)][payloadLen > 0 时: open(载荷 payloadLen+16)]
        [[nodiscard]] static auto verify_response(const view resp, const view psk) -> bool
        {
            if (resp.size() < 16 + 43)
                return false;
            const view salt(resp.data(), key_len);
            const auto key = session_key(psk, salt);
            chunk_codec codec(key);
            buffer fixed;
            if (!codec.open_raw(view(resp.data() + key_len, 43), fixed))
                return false;
            if (fixed.size() != 1 + 8 + key_len + 2 || fixed[0] != header_type_server)
                return false;
            const auto payload_len = static_cast<std::size_t>(
                (fixed[9 + key_len] << 8) | fixed[9 + key_len + 1]);
            if (payload_len == 0)
                return true;
            if (resp.size() < 16 + 43 + payload_len + aead_tag_len)
                return false;
            buffer payload;
            return codec.open_raw(view(resp.data() + key_len + 43, payload_len + aead_tag_len),
                                  payload);
        }

    private:
        std::array<std::uint8_t, key_len> psk_{};
        buffer fixed_buf_;
        buffer var_buf_;
    };

} // namespace psm_test::shadow2022
