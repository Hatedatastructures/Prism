/**
 * @file server.hpp
 * @brief VMess 服务端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 服务端模式：accept() 完成完整握手：
 *          1. 读取认证头 → 打开（KDF 校验 + 解密请求头）
 *          2. 解析请求头（FNV1a 校验 + 命令/安全校验）
 *          3. 发送响应长度 + 响应头（V 回显）
 *          4. 派生分块密钥，返回数据会话
 * @note 参考 mihomo transport/vmess/conn.go ServerConn。
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
#include <span>

namespace psmtest::vmess
{

    /// VMess 服务端配置
    struct server_config
    {
        /// 16 字节 UUID
        std::array<std::uint8_t, 16> uuid{};
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief VMess 服务端
    class server
    {
    public:
        /// @brief 构造
        /// @param cfg 服务端配置
        explicit server(const server_config &cfg)
            : cfg_(cfg), cmd_key_(cmd_key_from_uuid(cfg.uuid))
        {
        }

        /// 不可拷贝
        server(const server &) = delete;
        auto operator=(const server &) -> server & = delete;

        /// 获取执行器（accept 后有效）
        [[nodiscard]] auto executor() const -> net::any_io_executor
        {
            return ex_;
        }

        /// @brief 接收连接并完成 VMess 握手
        /// @param raw 底层传输
        /// @param target 输出参数：客户端请求的目标地址
        /// @param timeout 握手超时
        /// @return 数据会话；nullptr = 认证失败
        auto accept(std::shared_ptr<transport_base> raw, address &target,
                    std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<std::shared_ptr<session>>
        {
            if (!raw || !raw->is_open())
                co_return nullptr;
            ex_ = raw->executor();
            if (timeout.count() > 0)
                raw->set_timeout(timeout);
            // 1. 读取认证头前缀（16 authID + 18 len + 8 nonce = 42 字节）
            std::array<std::uint8_t, 42> prefix{};
            std::size_t done = 0;
            while (done < prefix.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(prefix.data() + done, prefix.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            // 认证 ID（AAD）
            std::array<std::uint8_t, 16> auth_id{};
            std::memcpy(auth_id.data(), prefix.data(), 16);

            // 2. 解密长度字段
            const auto len_key = kdf(cmd_key_, kdf_header_len_key, auth_id, std::span<const std::uint8_t>(prefix).subspan(34, 8));
            const auto len_iv = kdf(cmd_key_, kdf_header_len_iv, auth_id, std::span<const std::uint8_t>(prefix).subspan(34, 8));
            std::array<std::uint8_t, 16> lk{};
            std::memcpy(lk.data(), len_key.data(), 16);
            std::array<std::uint8_t, 12> liv{};
            std::memcpy(liv.data(), len_iv.data(), 12);
            const auto len_plain = detail::aes_gcm_open(
                lk, liv, std::span<const std::uint8_t>(prefix).subspan(16, 18), auth_id);
            if (len_plain.size() != 2)
                co_return nullptr;
            const auto body_len = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];

            // 3. 读取请求头密文（body_len + 16 tag）
            std::vector<std::uint8_t> body_enc(body_len + 16);
            done = 0;
            while (done < body_enc.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(body_enc.data() + done, body_enc.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            // 4. 解密请求头
            const auto hdr_key = kdf(cmd_key_, kdf_header_key, auth_id, std::span<const std::uint8_t>(prefix).subspan(34, 8));
            const auto hdr_iv = kdf(cmd_key_, kdf_header_iv, auth_id, std::span<const std::uint8_t>(prefix).subspan(34, 8));
            std::array<std::uint8_t, 16> hk{};
            std::memcpy(hk.data(), hdr_key.data(), 16);
            std::array<std::uint8_t, 12> hiv{};
            std::memcpy(hiv.data(), hdr_iv.data(), 12);
            auto plain = detail::aes_gcm_open(hk, hiv, body_enc, auth_id);
            if (plain.empty())
                co_return nullptr;

            // 解析请求头（校验 FNV1a，提取 IV/Key/V 与目标地址）
            request_header hdr{};
            std::array<std::uint8_t, 16> req_iv{};
            std::array<std::uint8_t, 16> req_key{};
            std::uint8_t v = 0;
            if (parse_request_header(plain, hdr, req_iv, req_key, v) != error::none)
                co_return nullptr;
            target = hdr.target;

            // 响应密钥：respBodyKey = sha256(reqKey)[:16]，respBodyIV = sha256(reqIV)[:16]
            const auto resp_body_key = detail::sha256(req_key);
            const auto resp_body_iv = detail::sha256(req_iv);
            std::array<std::uint8_t, 16> resp_key16{};
            std::memcpy(resp_key16.data(), resp_body_key.data(), 16);
            std::array<std::uint8_t, 16> resp_iv16{};
            std::memcpy(resp_iv16.data(), resp_body_iv.data(), 16);
            const std::array<std::uint8_t, 4> v_plain{v, 0, 0, 0};
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
            const auto len_enc = detail::aes_gcm_seal(
                rlk, rliv, resp_len_plain, auth_id);
            std::vector<std::uint8_t> resp;
            resp.reserve(len_enc.size() + resp_enc.size());
            resp.insert(resp.end(), len_enc.begin(), len_enc.end());
            resp.insert(resp.end(), resp_enc.begin(), resp_enc.end());
            const auto ec = co_await raw->write_all(resp);
            if (ec)
                co_return nullptr;

            // 5. 派生分块密钥（respBodyKey = KDF(reqKey, iv)）
            const auto body_key = kdf(req_key, req_iv);
            std::array<std::uint8_t, 16> chunk_key{};
            std::memcpy(chunk_key.data(), body_key.data(), 16);
            std::array<std::uint8_t, 12> chunk_nonce{};
            std::memcpy(chunk_nonce.data(), req_iv.data(), 12);

            session_options opt;
            opt.timeout = cfg_.timeout;
            co_return session::create(std::move(raw), chunk_key, chunk_nonce, opt);
        }

    private:
        server_config cfg_;
        std::array<std::uint8_t, 16> cmd_key_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::vmess
