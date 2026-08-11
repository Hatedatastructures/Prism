/**
 * @file handshake.hpp
 * @brief VMess 握手消息序列化器 / 解析器类（Beast 风格）
 * @details serializer：message + 时间戳 → 完整 AEAD 握手包
 *          （AuthID + LenEnc + Nonce + HdrEnc）；
 *          parser：握手包 → message（uuid / nonce / key / cmd / dst），
 *          UUID 不匹配返回 auth_failed；
 *          chunk_stream：基于 chunk_encryptor / chunk_decryptor 的
 *          会话级分块流封装（16 字节 IV，nonce 取前 12 字节）；
 *          make_response：构造 38 字节 AEAD 响应头
 *          （18 长度块 + 20 响应头块）。
 * @note 参考 tests/common/vmess/server.hpp 响应构造与 mihomo
 *       transport/vmess/conn.go sealVMessAEADHeader。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/vmess/chunk.hpp>
#include <common/vmess/codec.hpp>
#include <common/vmess/kdf.hpp>
#include <common/vmess/types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace psmtest::vmess
{

    /// @brief VMess 握手消息（Beast 风格，供 serializer/parser 使用）
    struct message
    {
        /// 客户端 UUID（16 字节）
        std::array<std::uint8_t, 16> uuid{};
        /// 请求 nonce（作为请求头 IV）
        std::array<std::uint8_t, 16> request_nonce{};
        /// 请求密钥（作为请求头 Key）
        std::array<std::uint8_t, 16> request_key{};
        /// 命令字节（cmd_tcp / cmd_udp / cmd_mux）
        std::uint8_t cmd{cmd_tcp};
        /// 目标地址
        address dst;
        /// 响应验证字节（请求头 V，响应头回显）
        std::uint8_t resp_header{0};
    };

    /// @brief VMess 握手序列化器（对象 → wire，Beast 风格）
    class serializer
    {
    public:
        /// @brief 构造
        /// @param uuid 客户端 UUID（16 字节）
        explicit serializer(const std::array<std::uint8_t, 16> &uuid)
            : uuid_(uuid)
        {
        }

        /// @brief 重置并绑定消息
        /// @param msg 消息
        /// @param time_sec UTC 秒（AuthID 用）
        auto reset(const message &msg, std::uint64_t time_sec) -> void
        {
            const auto cmd_key = cmd_key_from_uuid(uuid_);
            request_header hdr;
            hdr.version = protocol_version;
            hdr.cmd = static_cast<command>(msg.cmd);
            hdr.opt = 0;
            hdr.sec = security::aes_128_gcm;
            hdr.reserved = 0;
            hdr.target = msg.dst;
            const auto body = build_request_header(
                hdr, msg.request_nonce, msg.request_key, msg.resp_header, 0);

            std::random_device rd;
            std::array<std::uint8_t, 4> random{};
            for (auto &b : random)
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            wire_ = seal_auth_header(cmd_key, body, static_cast<std::int64_t>(time_sec), random);
            offset_ = 0;
        }

        /// @brief 增量输出
        /// @param buffer 输出缓冲区
        /// @param ec 错误码（成功 = 空）
        /// @return 实际写入字节数
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
        std::array<std::uint8_t, 16> uuid_;
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /// @brief VMess 握手解析器（wire → 对象，Beast 风格）
    class parser
    {
    public:
        /// @brief 构造
        /// @param uuid 客户端 UUID（16 字节，不匹配则 auth_failed）
        explicit parser(const std::array<std::uint8_t, 16> &uuid)
            : uuid_(uuid)
        {
        }

        /// @brief 增量喂入
        /// @param buffer 输入缓冲区
        /// @param ec 错误码（auth_failed = UUID 不匹配，need_more = 数据不足）
        /// @return 已累积缓冲字节数
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            if (done_)
                return buf_.size();
            const auto data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(buffer.data()), buffer.size());
            buf_.insert(buf_.end(), data.begin(), data.end());
            if (buf_.size() < 16 + 18 + 8 + 18)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }

            const auto cmd_key = cmd_key_from_uuid(uuid_);
            const auto auth_id = std::span<const std::uint8_t>(buf_).first(16);
            const auto len_enc = std::span<const std::uint8_t>(buf_).subspan(16, 18);
            const auto nonce8 = std::span<const std::uint8_t>(buf_).subspan(34, 8);

            // 先解长度块，确定请求头密文总长
            const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, nonce8);
            const auto len_iv = kdf(cmd_key, kdf_header_len_iv, auth_id, nonce8);
            std::array<std::uint8_t, 16> lk{};
            std::memcpy(lk.data(), len_key.data(), 16);
            std::array<std::uint8_t, 12> liv{};
            std::memcpy(liv.data(), len_iv.data(), 12);
            const auto len_plain = detail::aes_gcm_open(lk, liv, len_enc, auth_id);
            if (len_plain.size() != 2)
            {
                ec = make_error_code(error::auth_failed);
                return 0;
            }
            const auto length = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];
            const auto total = 16 + 18 + 8 + length + 16;
            if (buf_.size() < total)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }

            // 解请求头并校验 FNV1a
            std::vector<std::uint8_t> body;
            const auto err = open_auth_header(cmd_key, std::span<const std::uint8_t>(buf_).first(total), body);
            if (err != error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            request_header hdr{};
            std::array<std::uint8_t, 16> iv{};
            std::array<std::uint8_t, 16> key{};
            std::uint8_t v = 0;
            const auto perr = parse_request_header(body, hdr, iv, key, v);
            if (perr != error::none)
            {
                ec = make_error_code(perr);
                return 0;
            }

            msg_.uuid = uuid_;
            msg_.request_nonce = iv;
            msg_.request_key = key;
            msg_.cmd = static_cast<std::uint8_t>(hdr.cmd);
            msg_.dst = hdr.target;
            msg_.resp_header = v;
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
        std::array<std::uint8_t, 16> uuid_;
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool done_{false};
    };

    /// @brief VMess 会话级分块流（Beast 风格封装）
    /// @details 内部持有独立 nonce 的加密器 / 解密器各一：
    ///          encrypt 与 decrypt 各自推进 nonce，方向相反时密钥互逆。
    class chunk_stream
    {
    public:
        /// 解密结果
        struct result
        {
            /// 错误码（error::none 成功）
            std::error_code ec;
            /// 已消耗 wire 字节数
            std::size_t consumed{0};
        };

        /// @brief 初始化
        /// @param key 16 字节分块密钥
        /// @param iv 16 字节分块 IV（chunk nonce 取前 12 字节）
        auto init(std::span<const std::uint8_t, 16> key, std::span<const std::uint8_t, 16> iv) -> void
        {
            std::array<std::uint8_t, 12> nonce{};
            std::memcpy(nonce.data(), iv.data(), 12);
            enc_ = chunk_encryptor(key, nonce);
            dec_ = chunk_decryptor(key, nonce);
        }

        /// @brief 加密一块载荷
        /// @param payload 明文
        /// @param wire 输出密文（含块头与 tag）
        /// @return false = 成功
        auto encrypt(std::span<const std::uint8_t> payload, std::string &wire) -> bool
        {
            std::vector<std::uint8_t> out(payload.size() + chunk_encryptor::overhead);
            const auto n = enc_.seal(payload, out);
            wire.assign(reinterpret_cast<const char *>(out.data()), n);
            return false;
        }

        /// @brief 解密一块密文
        /// @param wire 密文（完整块：长度 + tag + 载荷 + tag）
        /// @param plain 输出明文
        /// @return 解密结果
        auto decrypt(std::span<const std::uint8_t> wire, std::string &plain) -> result
        {
            result r;
            if (wire.size() < 18)
            {
                r.ec = make_error_code(error::need_more);
                return r;
            }
            std::vector<std::uint8_t> out(wire.size());
            std::size_t consumed = 0;
            const auto ec = dec_.open(wire, out, consumed);
            if (ec != error::none)
            {
                r.ec = make_error_code(ec);
                return r;
            }
            plain.assign(reinterpret_cast<const char *>(out.data()), consumed - 18 - 16);
            r.consumed = consumed;
            return r;
        }

    private:
        chunk_encryptor enc_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
        chunk_decryptor dec_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
    };

    /// @brief 构造 VMess AEAD 响应头（Beast 风格）
    /// @details 响应 = [18B 长度块] + [20B 响应头块] = 38 字节：
    ///          respBodyKey = sha256(request_key)[:16]
    ///          respBodyIV  = sha256(request_nonce)[:16]
    ///          AAD = 随机 AuthID（内部生成）
    /// @param msg 请求消息（request_key / request_nonce / resp_header）
    /// @param resp 输出响应字节
    /// @return false = 成功
    [[nodiscard]] inline auto make_response(const message &msg, std::string &resp) -> bool
    {
        const auto resp_body_key = detail::sha256(msg.request_key);
        const auto resp_body_iv = detail::sha256(msg.request_nonce);
        std::array<std::uint8_t, 16> resp_key16{};
        std::memcpy(resp_key16.data(), resp_body_key.data(), 16);
        std::array<std::uint8_t, 16> resp_iv16{};
        std::memcpy(resp_iv16.data(), resp_body_iv.data(), 16);

        std::random_device rd;
        std::array<std::uint8_t, 4> random{};
        for (auto &b : random)
            b = static_cast<std::uint8_t>(rd() & 0xFF);
        const auto auth_id = create_auth_id(static_cast<std::int64_t>(std::time(nullptr)), random);

        const std::array<std::uint8_t, 4> v_plain{msg.resp_header, 0, 0, 0};
        const auto resp_key = kdf(resp_key16, kdf_resp_key);
        const auto resp_iv = kdf(resp_iv16, kdf_resp_iv);
        std::array<std::uint8_t, 16> rk{};
        std::memcpy(rk.data(), resp_key.data(), 16);
        std::array<std::uint8_t, 12> riv{};
        std::memcpy(riv.data(), resp_iv.data(), 12);
        const auto resp_enc = seal_response_header(rk, riv, v_plain, auth_id);

        const auto resp_len_key = kdf(resp_key16, kdf_resp_len_key);
        const auto resp_len_iv = kdf(resp_iv16, kdf_resp_len_iv);
        std::array<std::uint8_t, 16> rlk{};
        std::memcpy(rlk.data(), resp_len_key.data(), 16);
        std::array<std::uint8_t, 12> rliv{};
        std::memcpy(rliv.data(), resp_len_iv.data(), 12);
        const std::array<std::uint8_t, 2> resp_len_plain{
            static_cast<std::uint8_t>(resp_enc.size() >> 8),
            static_cast<std::uint8_t>(resp_enc.size() & 0xFF)};
        const auto len_enc = detail::aes_gcm_seal(rlk, rliv, resp_len_plain, auth_id);

        resp.clear();
        resp.reserve(len_enc.size() + resp_enc.size());
        resp.insert(resp.end(), len_enc.begin(), len_enc.end());
        resp.insert(resp.end(), resp_enc.begin(), resp_enc.end());
        return false;
    }

} // namespace psmtest::vmess
