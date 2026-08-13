/**
 * @file conn.hpp
 * @brief ShadowTLS v3 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 ShadowTLS v3 连接（对齐 sing v3 客户端）：
 * 1. write_handshake：构造 ClientHello 帧（session_id 内嵌 HMAC 认证码）
 * 2. read_handshake：服务端校验 ClientHello session_id HMAC
 * 3. 握手后数据面透传（帧 HMAC 认证由上层负责，测试库简化透传）
 * @note 与 shadowtls.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/stealth/shadowtls/codec.hpp>
#include <common/stealth/shadowtls/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace psmtest::shadowtls
{

    /**
     * @class conn
     * @brief ShadowTLS v3 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后通过
     * transmission 接口透传数据。
     */
    class conn : public psmtest::transmission,
                 public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         * @param password 认证密码
         */
        explicit conn(shared_transmission upstream, std::string password)
            : next_layer_(std::move(upstream)), password_(std::move(password))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 客户端握手：构造并发送带认证 session_id 的 ClientHello 帧
         * @param server_random 服务端随机数（32 字节，真实 TLS 中由握手生成）
         * @param client_random 客户端随机数（32 字节）
         * @return 错误码
         * @details 构造简化 ClientHello：TLS 记录头(5) + 握手头(4) +
         * version(2) + random(32) + sidLen(1) + session_id(32)，
         * session_id 末尾 4 字节为 HMAC 认证码。
         */
        [[nodiscard]] auto write_handshake(std::span<const std::uint8_t> server_random,
                                           std::span<const std::uint8_t> client_random)
        -> net::awaitable<error>
        {
            std::vector<std::uint8_t> hello = build_client_hello(client_random);

            // 构造 session_id：前 28 字节固定模式 + 末尾 4 字节 HMAC
            std::array<std::uint8_t, tls_session_id_sz> session_id{};
            for (std::size_t i = 0; i < tls_session_id_sz - hmac_size; ++i)
                session_id[i] = static_cast<std::uint8_t>(i * 7 + 3);
            const auto hmac_hello = std::span<const std::uint8_t>(hello).subspan(tls_hdrsize);
            auto err = generate_session_id(session_id_input{password_, hmac_hello, session_id});
            if (err != error::none)
                co_return err;
            std::memcpy(hello.data() + tls_hdrsize + session_id_start, session_id.data(),
                        tls_session_id_sz);

            if (co_await send_bytes(hello))
                co_return error::io_error;

            // 保存会话状态
            server_random_.assign(server_random.begin(), server_random.end());
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：读取并校验 ClientHello session_id HMAC
         * @return 错误码
         */
        [[nodiscard]] auto read_handshake()
        -> net::awaitable<error>
        {
            // 完整 hello：TLS 头 + 握手头 + version + random + sidLen + session_id + 尾部
            constexpr std::size_t hello_len =
                tls_hdrsize + session_id_start + tls_session_id_sz + 16;
            std::vector<std::uint8_t> hello(hello_len);
            if (co_await read_exact(hello))
                co_return error::unexpected_eof;
            const auto hello_span = as_bytes_span(hello);
            if (!verify_client_hello(password_, hello_span))
                co_return error::bad_auth;
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 透传读取（握手后数据面为裸流）
         */
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

        /**
         * @brief 透传写入（握手后数据面为裸流）
         */
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

        /**
         * @brief 关闭底层传输
         */
        void close() override
        {
            next_layer_->close();
        }

        /**
         * @brief 取消挂起操作
         */
        void cancel() override
        {
            next_layer_->cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto next_layer() noexcept -> psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto next_layer() const noexcept -> const psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto release() -> shared_transmission override
        {
            return std::move(next_layer_);
        }

    private:
        /**
         * @brief 构造简化 ClientHello（无 TLS 头版本的握手数据）
         * @param client_random 32 字节客户端随机数
         * @return 完整 ClientHello（含 TLS 记录头 5 字节）
         */
        [[nodiscard]] auto build_client_hello(std::span<const std::uint8_t> client_random)
        -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> hello(tls_hdrsize + session_id_start + tls_session_id_sz + 16,
                                             0);
            hello[0] = 0x16; // content_handshake
            hello[tls_hdrsize] = hs_type_clienthello;
            hello[tls_hdrsize + session_id_start - 1] = tls_session_id_sz;
            if (client_random.size() >= tls_rnd_size)
            {
                std::memcpy(hello.data() + tls_hdrsize + 1 + 3 + 2, client_random.data(),
                            tls_rnd_size);
            }
            return hello;
        }

        /**
         * @brief 精确读取指定字节数
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto read_exact(std::span<std::uint8_t> dst)
        -> net::awaitable<bool>
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

        shared_transmission next_layer_;      ///< 底层传输（独占所有权）
        std::string password_;                ///< 认证密码
        std::vector<std::uint8_t> server_random_; ///< 服务端随机数（握手后）
        bool handshaken_{false};              ///< 握手完成标志
    };

    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn>;

    static_assert(psmtest::transmission_like<conn>);

} // namespace psmtest::shadowtls
