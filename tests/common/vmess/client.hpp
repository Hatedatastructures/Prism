/**
 * @file client.hpp
 * @brief VMess 客户端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 客户端模式：持有 UUID/cmdKey 等配置，
 *          connect() 完成完整握手：
 *          1. 生成随机 IV/Key/验证字节/填充
 *          2. 构造请求头明文 → 密封 AEAD 认证头
 *          3. 发送
 *          4. 读取响应长度 + 响应头（AAD = authID）
 *          5. 校验 V，派生分块密钥，返回数据会话
 * @note 参考 mihomo transport/vmess/conn.go ClientConn。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/vmess/codec.hpp>
#include <common/vmess/kdf.hpp>
#include <common/vmess/session.hpp>
#include <common/vmess/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <random>
#include <span>

namespace psmtest::vmess
{

    /// VMess 客户端配置
    struct client_config
    {
        /// 16 字节 UUID
        std::array<std::uint8_t, 16> uuid{};
        /// 安全类型（默认 AES-128-GCM）
        security sec{security::aes_128_gcm};
        /// 命令（默认 TCP）
        command cmd{command::tcp};
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief VMess 客户端
    class client
    {
    public:
        /// @brief 构造
        /// @param cfg 客户端配置
        explicit client(const client_config &cfg)
            : cfg_(cfg), cmd_key_(cmd_key_from_uuid(cfg.uuid))
        {
        }

        /// 不可拷贝
        client(const client &) = delete;
        auto operator=(const client &) -> client & = delete;

        /// 获取执行器（连接后有效）
        [[nodiscard]] auto executor() const -> net::any_io_executor
        {
            return ex_;
        }

        /// @brief 建立连接并完成 VMess 握手
        /// @param raw 底层传输
        /// @param target 目标地址
        /// @param timeout 握手超时
        /// @return 数据会话；nullptr = 握手失败
        auto connect(std::shared_ptr<transport_base> raw, const address &target,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<std::shared_ptr<session>>
        {
            if (!raw || !raw->is_open())
                co_return nullptr;
            ex_ = raw->executor();
            if (timeout.count() > 0)
                raw->set_timeout(timeout);

            // 1. 生成随机参数
            std::random_device rd;
            std::array<std::uint8_t, 16> iv{};
            std::array<std::uint8_t, 16> key{};
            for (auto &b : iv)
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            for (auto &b : key)
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            const auto v = static_cast<std::uint8_t>(rd() & 0xFF);
            const auto p = static_cast<std::uint8_t>(rd() % 16);
            std::array<std::uint8_t, 4> random4{};
            for (auto &b : random4)
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            const auto time_sec = std::chrono::system_clock::now().time_since_epoch().count() / 1000000000;

            // 2. 构造请求头并密封
            request_header hdr;
            hdr.version = protocol_version;
            hdr.cmd = cfg_.cmd;
            hdr.opt = 0x01; // chunk_stream
            hdr.sec = cfg_.sec;
            hdr.target = target;
            const auto plain = build_request_header(hdr, iv, key, v, p);
            const auto sealed = seal_auth_header(cmd_key_, plain, time_sec, random4);
            auth_id_ = create_auth_id(time_sec, random4);

            // 3. 发送认证头
            const auto ec = co_await raw->write_all(sealed);
            if (ec)
                co_return nullptr;

            // 4. 读取响应（2 字节长度密文 + 18）
            std::array<std::uint8_t, 18> len_enc{};
            std::size_t done = 0;
            while (done < len_enc.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(len_enc.data() + done, len_enc.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            // 响应密钥：respBodyKey = sha256(reqKey)[:16]，respBodyIV = sha256(reqIV)[:16]
            const auto resp_body_key = detail::sha256(key);
            const auto resp_body_iv = detail::sha256(iv);
            std::array<std::uint8_t, 16> resp_key16{};
            std::memcpy(resp_key16.data(), resp_body_key.data(), 16);
            std::array<std::uint8_t, 16> resp_iv16{};
            std::memcpy(resp_iv16.data(), resp_body_iv.data(), 16);

            const auto resp_len_key = kdf(resp_key16, kdf_resp_len_key);
            const auto resp_len_iv = kdf(resp_iv16, kdf_resp_len_iv);
            std::array<std::uint8_t, 16> rlk{};
            std::memcpy(rlk.data(), resp_len_key.data(), 16);
            std::array<std::uint8_t, 12> rliv{};
            std::memcpy(rliv.data(), resp_len_iv.data(), 12);
            const auto len_plain = detail::aes_gcm_open(rlk, rliv, len_enc, auth_id_);
            if (len_plain.size() != 2)
                co_return nullptr;
            // 响应头长度（已含 tag）
            const auto resp_len = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];

            // 5. 读取响应头（resp_len 已含 tag）
            std::vector<std::uint8_t> resp_enc(resp_len);
            done = 0;
            while (done < resp_enc.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(resp_enc.data() + done, resp_enc.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            const auto resp_key = kdf(resp_key16, kdf_resp_key);
            const auto resp_iv = kdf(resp_iv16, kdf_resp_iv);
            std::array<std::uint8_t, 16> rk{};
            std::memcpy(rk.data(), resp_key.data(), 16);
            std::array<std::uint8_t, 12> riv{};
            std::memcpy(riv.data(), resp_iv.data(), 12);
            response_header rh;
            const auto resp_ec = open_response_header(rk, riv, resp_enc, auth_id_, rh);

            if (resp_ec != error::none)
                co_return nullptr;
            if (rh.version != v)
                co_return nullptr;

            // 6. 派生分块密钥（respBodyKey = KDF(reqKey, iv) 的 sha256 前 16 字节）
            const auto body_key = kdf(key, iv);
            std::array<std::uint8_t, 16> chunk_key{};
            std::memcpy(chunk_key.data(), body_key.data(), 16);
            std::array<std::uint8_t, 12> chunk_nonce{};
            std::memcpy(chunk_nonce.data(), iv.data(), 12);

            session_options opt;
            opt.timeout = cfg_.timeout;
            co_return session::create(std::move(raw), chunk_key, chunk_nonce, opt);
        }

    private:
        client_config cfg_;
        std::array<std::uint8_t, 16> cmd_key_;
        std::array<std::uint8_t, 16> auth_id_{};
        net::any_io_executor ex_;
    };

} // namespace psmtest::vmess
