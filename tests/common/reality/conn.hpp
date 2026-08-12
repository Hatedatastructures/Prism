/**
 * @file conn.hpp
 * @brief Reality 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 Reality 连接（对齐 mihomo
 * component/tls/reality.go）：
 * 1. write_handshake：客户端生成 X25519 临时密钥对 → 派生 auth_key
 *    → seal session_id（短 ID 内嵌）
 * 2. read_handshake：服务端 X25519 共享密钥 → 派生 auth_key
 *    → open session_id 校验
 * 3. 数据面：TLS 1.3 记录透传（测试库简化）
 * @note 与 reality.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/reality/codec.hpp>
#include <common/reality/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace psmtest::reality
{

    /**
     * @class conn
     * @brief Reality 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     */
    class conn : public psmtest::transmission,
                 public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         * @param private_key 服务端/客户端 X25519 私钥（32 字节）
         */
        explicit conn(shared_transmission upstream, std::array<std::uint8_t, key_len> private_key)
            : next_layer_(std::move(upstream)), private_key_(private_key)
        {
        }

        /// @brief 获取执行器（委托底层传输）
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 客户端握手：派生 auth_key + seal session_id 并发送
         * @param peer_public_key 服务端公钥（32 字节）
         * @param client_random 客户端随机数（40 字节）
         * @param hello ClientHello 原始消息（AAD）
         * @param short_id 短 ID（8 字节）
         * @return 错误码
         */
        [[nodiscard]] auto write_handshake(std::span<const std::uint8_t> peer_public_key,
                                           std::span<const std::uint8_t> client_random,
                                           std::span<const std::uint8_t> hello,
                                           const std::array<std::uint8_t, max_short_id_len> &short_id)
            -> net::awaitable<error>
        {
            // X25519 共享密钥
            std::array<std::uint8_t, key_len> shared{};
            if (x25519_shared(private_key_, peer_public_key, shared))
                co_return error::kdf_error;
            shared_secret_ = shared;

            // 派生 auth_key
            std::array<std::uint8_t, key_len> auth_key{};
            if (derive_auth_key(shared, client_random, auth_key))
                co_return error::kdf_error;
            auth_key_ = auth_key;

            // 构造明文 session_id：version(1) + random(7) + short_id(8)
            std::array<std::uint8_t, 16> plain{};
            plain[0] = 0x01;
            std::copy(short_id.begin(), short_id.end(), plain.begin() + 8);

            // seal 并发送
            std::array<std::uint8_t, session_id_auth_len> sealed{};
            if (seal_session_id(auth_key, client_random, plain, hello, sealed))
                co_return error::kdf_error;
            session_id_ = sealed;
            if (co_await send_bytes(sealed))
            {
                std::fprintf(stderr, "[reality] send sealed sid failed\n");
                co_return error::io_error;
            }
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：读取 session_id → 派生 auth_key → 校验
         * @param peer_public_key 客户端公钥（32 字节）
         * @param client_random 客户端随机数（40 字节）
         * @param hello ClientHello 原始消息（AAD）
         * @param short_id 输出短 ID（8 字节）
         * @return 错误码；bad_auth = 解密失败或版本不匹配
         */
        [[nodiscard]] auto read_handshake(std::span<const std::uint8_t> peer_public_key,
                                          std::span<const std::uint8_t> client_random,
                                          std::span<const std::uint8_t> hello,
                                          std::array<std::uint8_t, max_short_id_len> &short_id)
            -> net::awaitable<error>
        {
            // 读取客户端 session_id 密文（32 字节）
            std::array<std::uint8_t, session_id_auth_len> session_id{};
            if (co_await read_exact(std::span<std::uint8_t>(session_id)))
                co_return error::unexpected_eof;

            std::array<std::uint8_t, key_len> shared{};
            if (x25519_shared(private_key_, peer_public_key, shared))
                co_return error::kdf_error;
            shared_secret_ = shared;

            std::array<std::uint8_t, key_len> auth_key{};
            if (derive_auth_key(shared, client_random, auth_key))
                co_return error::kdf_error;
            auth_key_ = auth_key;

            std::array<std::uint8_t, 16> plain{};
            if (open_session_id(auth_key, client_random, session_id, hello, plain))
                co_return error::bad_auth;
            if (plain[0] != 0x01)
                co_return error::bad_auth;
            std::copy(plain.begin() + 8, plain.begin() + 16, short_id.begin());
            handshaken_ = true;
            co_return error::none;
        }

        /// @brief 透传读取（数据面原样）
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(error::not_open);
                co_return 0;
            }
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /// @brief 透传写入（数据面原样）
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer,
                                            std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(error::not_open);
                co_return 0;
            }
            co_return co_await next_layer_->async_write_some(buffer, ec);
        }

        /// @brief 关闭底层传输
        void close() override
        {
            next_layer_->close();
        }

        /// @brief 取消挂起操作
        void cancel() override
        {
            next_layer_->cancel();
        }

        /// @brief 获取底层传输（装饰器链导航）
        [[nodiscard]] auto next_layer() noexcept -> psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /// @brief 获取底层传输（const 版本）
        [[nodiscard]] auto next_layer() const noexcept -> const psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /// @brief 释放底层传输所有权
        [[nodiscard]] auto release() -> shared_transmission override
        {
            return std::move(next_layer_);
        }

        /// @brief 获取派生认证密钥（握手后有效）
        [[nodiscard]] auto auth_key() const -> const std::array<std::uint8_t, key_len> &
        {
            return auth_key_;
        }

        /// @brief 获取共享密钥（握手后有效）
        [[nodiscard]] auto shared_secret() const -> const std::array<std::uint8_t, key_len> &
        {
            return shared_secret_;
        }

        /// @brief 获取 seal 后的 session_id（客户端握手后有效）
        [[nodiscard]] auto session_id() const -> const std::array<std::uint8_t, session_id_auth_len> &
        {
            return session_id_;
        }

    private:
        /**
         * @brief 精确读取指定字节数
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto read_exact(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < dst.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(as_bytes(dst.subspan(done)), ec);
                if (ec || n == 0)
                    co_return true;
                done += n;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto send_bytes(std::span<const std::uint8_t> data) const
            -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < data.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(as_bytes(data.subspan(done)), ec);
                if (ec)
                    co_return true;
                done += n;
            }
            co_return false;
        }

        shared_transmission next_layer_;                              ///< 底层传输（独占所有权）
        std::array<std::uint8_t, key_len> private_key_{};             ///< X25519 私钥
        std::array<std::uint8_t, key_len> shared_secret_{};           ///< 共享密钥
        std::array<std::uint8_t, key_len> auth_key_{};                ///< 认证密钥
        std::array<std::uint8_t, session_id_auth_len> session_id_{};  ///< seal 后的 session_id
        bool handshaken_{false};                                      ///< 握手完成标志
    };

    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn>;

    static_assert(psmtest::transmission_like<conn>);

} // namespace psmtest::reality
