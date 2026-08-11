/**
 * @file server.hpp
 * @brief Shadowsocks 2022 服务端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 服务端模式：accept() 完成握手：
 *          1. 读取 salt（16 字节）
 *          2. 派生会话密钥
 *          3. 读取并解密固定头（时间窗校验）
 *          4. 读取并解密变长头（地址解析）
 *          5. 发送响应固定头
 *          6. 返回分块会话
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
#include <span>

namespace psmtest::ss2022
{

    /// SS2022 服务端配置
    struct server_config
    {
        /// 预共享密钥（16 字节 aes-128-gcm）
        std::array<std::uint8_t, 16> psk{};
        /// 时间容忍窗口（秒）
        std::uint64_t time_window{90};
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief Shadowsocks 2022 服务端
    class server
    {
    public:
        /// @brief 构造
        /// @param cfg 服务端配置
        explicit server(const server_config &cfg)
            : cfg_(cfg)
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

        /// @brief 接收连接并完成 SS2022 握手
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

            // 1. 读取 salt（16 字节）
            std::array<std::uint8_t, 16> salt{};
            std::size_t done = 0;
            while (done < salt.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(salt.data() + done, salt.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }

            // 2. 派生会话密钥
            const auto key = session_key(cfg_.psk, salt, 16);

            // 3. 读取并解密固定头（seal 输出 = 18B len + 27B body）
            std::array<std::uint8_t, len_block_size + fixed_hdr_size> fixed_enc{};
            done = 0;
            while (done < fixed_enc.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(fixed_enc.data() + done, fixed_enc.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            chunk_codec codec(key);
            std::size_t consumed = 0;
            const auto fixed_plain = codec.open(fixed_enc, consumed);
            if (fixed_plain.size() != fixed_hdr_plain)
                co_return nullptr;
            if (fixed_plain[0] != header_type_client)
                co_return nullptr;

            // 时间戳校验
            std::uint64_t ts = 0;
            for (std::size_t i = 0; i < 8; ++i)
                ts = (ts << 8) | fixed_plain[1 + i];
            const auto now = static_cast<std::uint64_t>(
                std::chrono::system_clock::now().time_since_epoch().count() / 1000000000);
            const auto diff = now > ts ? now - ts : ts - now;
            const auto var_len = static_cast<std::size_t>(fixed_plain[9]) << 8 | fixed_plain[10];
            if (diff > cfg_.time_window)
                co_return nullptr;

            // 4. 读取并解密变长头（seal 输出 = 18B len + var_len + 16B tag）
            std::vector<std::uint8_t> var_enc(len_block_size + var_len + aead_tag_len);
            done = 0;
            while (done < var_enc.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(var_enc.data() + done, var_enc.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            const auto var_plain = codec.open(var_enc, consumed);
            if (var_plain.empty())
                co_return nullptr;
            std::span<const std::uint8_t> payload;
            if (parse_var_header(var_plain, target, payload) != error::none)
                co_return nullptr;

            // 5. 发送响应固定头（独立 nonce：响应方向从 0 开始）
            chunk_codec resp_codec(key);
            const auto resp_plain = build_fixed_header(header_type_server,
                                                       static_cast<std::uint64_t>(
                                                           std::chrono::system_clock::now().time_since_epoch().count() / 1000000000),
                                                       0);
            const auto resp_enc = resp_codec.seal(resp_plain);
            const auto ec = co_await raw->write_all(resp_enc);
            if (ec)
                co_return nullptr;

            session_options opt;
            opt.timeout = cfg_.timeout;
            // 接收侧用 codec（握手已消耗 nonce 0-3），发送侧用 resp_codec（nonce 0）
            co_return session::create(std::move(raw), std::move(resp_codec), std::move(codec), opt);
        }

    private:
        server_config cfg_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::ss2022
