/**
 * @file client.hpp
 * @brief Shadowsocks 2022 客户端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 客户端模式：connect() 完成握手：
 *          1. 生成随机 salt
 *          2. 派生会话密钥（BLAKE3 DeriveKey）
 *          3. 构造固定头（type + 时间戳 + 变长头长度）
 *          4. 构造变长头（地址 + padding）
 *          5. 加密并发送 [salt][固定头密文][变长头密文]
 *          6. 读取并校验响应固定头
 *          7. 返回分块会话
 * @note 参考 SIP022 规范与 mihomo transport/shadowsocks2022。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/shadowsocks2022/chunk.hpp>
#include <common/shadowsocks2022/codec.hpp>
#include <common/shadowsocks2022/kdf.hpp>
#include <common/shadowsocks2022/session.hpp>
#include <common/shadowsocks2022/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <random>
#include <span>

namespace psmtest::ss2022
{

    /// SS2022 客户端配置
    struct client_config
    {
        /// 预共享密钥（16 字节 aes-128-gcm）
        std::array<std::uint8_t, 16> psk{};
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief Shadowsocks 2022 客户端
    class client
    {
    public:
        /// @brief 构造
        /// @param cfg 客户端配置
        explicit client(const client_config &cfg)
            : cfg_(cfg)
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

        /// @brief 建立连接并完成 SS2022 握手
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

            // 1. 生成随机 salt
            std::random_device rd;
            std::array<std::uint8_t, 16> salt{};
            for (auto &b : salt)
                b = static_cast<std::uint8_t>(rd() & 0xFF);

            // 2. 派生会话密钥
            const auto key = session_key(cfg_.psk, salt, 16);

            // 3. 固定头 + 变长头
            const auto time_sec = std::chrono::system_clock::now().time_since_epoch().count() / 1000000000;
            const auto pad_len = static_cast<std::uint16_t>(1 + rd() % 16);
            const auto var_plain = build_var_header(target, pad_len);
            const auto fixed_plain = build_fixed_header(header_type_client, time_sec,
                                                        static_cast<std::uint16_t>(var_plain.size()));

            // 4. 加密
            chunk_codec codec(key);
            const auto fixed_enc = codec.seal(fixed_plain);
            const auto var_enc = codec.seal(var_plain);

            // 5. 发送 [salt][fixed][var]
            std::vector<std::uint8_t> handshake;
            handshake.reserve(salt.size() + fixed_enc.size() + var_enc.size());
            handshake.insert(handshake.end(), salt.begin(), salt.end());
            handshake.insert(handshake.end(), fixed_enc.begin(), fixed_enc.end());
            handshake.insert(handshake.end(), var_enc.begin(), var_enc.end());
            const auto ec = co_await raw->write_all(handshake);
            if (ec)
                co_return nullptr;

            // 6. 读取响应（服务端 seal 输出 = 18B len 块 + 27B 固定头密文）
            std::array<std::uint8_t, len_block_size + fixed_hdr_size> resp_enc{};
            std::size_t done = 0;
            while (done < resp_enc.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(resp_enc.data() + done, resp_enc.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            chunk_codec resp_codec(key);
            const auto resp_plain = resp_codec.open(resp_enc, done);
            if (resp_plain.size() != fixed_hdr_plain)
                co_return nullptr;
            if (resp_plain[0] != header_type_server)
                co_return nullptr;

            session_options opt;
            opt.timeout = cfg_.timeout;
            // 发送侧用 codec（握手已消耗 nonce 0-3），接收侧用 resp_codec（nonce 0）
            co_return session::create(std::move(raw), std::move(codec), std::move(resp_codec), opt);
        }

    private:
        client_config cfg_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::ss2022
