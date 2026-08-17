/**
 * @file conn.hpp
 * @brief AnyTLS 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 AnyTLS 连接（对齐 mihomo transport/anytls）：
 * 1. write_handshake：发送认证帧 [SHA-256(password)][padlen][padding]
 * 2. read_handshake：服务端读取认证帧并校验密码哈希
 * 3. 数据面：内部多路复用（session 帧），测试库简化透传
 * @note 与 anytls.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/anytls/codec.hpp>
#include <common/protocols/anytls/types.hpp>

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

namespace preview::anytls
{

    /**
     * @class conn
     * @brief AnyTLS 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB arena；可注入自定义策略）
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    class conn : public preview::transmission, public std::enable_shared_from_this<conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using memory_type = Memory;

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
        [[nodiscard]] auto executor() const 
            -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 客户端握手：发送认证帧
         * @param pad_len Padding 长度（默认 16）
         * @return 错误码
         */
        [[nodiscard]] auto write_handshake(std::uint16_t pad_len = 16)
            -> net::awaitable<error>
        {
            std::string frame;
            auto err = build_auth_frame(password_, pad_len, frame);
            if (err != error::none)
                co_return err;
            if (co_await send_bytes(as_u8_span(frame)))
                co_return error::io_error;
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：读取并校验认证帧
         * @return 错误码；bad_auth = 密码哈希不匹配
         */
        [[nodiscard]] auto read_handshake()
            -> net::awaitable<error>
        {
            // 头：hash(32) + pad_len(2 BE)
            std::array<std::uint8_t, auth_frame_hdrlen> head{};
            if (co_await read_exact(std::span<std::uint8_t>(head)))
                co_return error::unexpected_eof;
            std::array<std::uint8_t, password_hash_len> hash{};
            std::memcpy(hash.data(), head.data(), password_hash_len);
            const auto pad_len = static_cast<std::uint16_t>(head[password_hash_len]) << 8 |
                                 head[password_hash_len + 1];
            if (pad_len > 0)
            {
                std::vector<std::uint8_t> padding(pad_len);
                if (co_await read_exact(padding))
                    co_return error::unexpected_eof;
            }
            if (!verify_auth(password_, hash))
                co_return error::bad_auth;
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 透传读取（数据面原样）
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
         * @brief 透传写入（数据面原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
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
        [[nodiscard]] auto next_layer() noexcept 
            -> preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto next_layer() const noexcept
             -> const preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto release() 
            -> shared_transmission override
        {
            return std::move(next_layer_);
        }

    private:
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

        shared_transmission next_layer_;  ///< 底层传输（独占所有权）
        std::string password_;            ///< 认证密码
        bool handshaken_{false};          ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using shared_conn = std::shared_ptr<conn<>>;

    static_assert(preview::transmission_like<conn<>>);

} // namespace preview::anytls
