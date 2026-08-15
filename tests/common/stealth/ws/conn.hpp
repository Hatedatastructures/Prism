/**
 * @file conn.hpp
 * @brief WebSocket 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 WebSocket 连接（对齐 mihomo transport/ws）：
 * 1. write_handshake / read_handshake：HTTP 升级握手
 *    （Sec-WebSocket-Key/Accept 交换）
 * 2. 数据面：帧编解码（codec.hpp 纯函数），本类负责帧边界恢复
 * @note 与 ws.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transmission.hpp>
#include <common/stealth/ws/codec.hpp>
#include <common/stealth/ws/types.hpp>

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

namespace psmtest::ws
{

    /**
     * @class conn
     * @brief WebSocket 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面
     * 为帧边界恢复后的裸流。
     * @tparam Memory 会话内存策略（默认 8KB arena；可注入自定义策略）
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    class conn : public psmtest::transmission,
                 public std::enable_shared_from_this<conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using memory_type = Memory;
        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         */
        explicit conn(shared_transmission upstream)
            : next_layer_(std::move(upstream))
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
         * @brief 客户端握手：发送 Upgrade 请求并等待 101 响应
         * @param key Sec-WebSocket-Key（base64 24 字符）
         * @param host 目标主机
         * @return 错误码；bad_auth = Accept 不匹配
         */
        [[nodiscard]] auto write_handshake(std::string_view key, std::string_view host)
        -> net::awaitable<error>
        {
            std::string header;
            header.reserve(128 + host.size() + key.size());
            header += "GET / HTTP/1.1\r\n";
            header += "Host: " + std::string(host) + "\r\n";
            header += "Upgrade: websocket\r\n";
            header += "Connection: Upgrade\r\n";
            header += "Sec-WebSocket-Key: " + std::string(key) + "\r\n";
            header += "Sec-WebSocket-Version: 13\r\n";
            header += "\r\n";
            if (co_await send_bytes(as_u8_span(header)))
                co_return error::io_error;

            // 等待 101 响应并校验 Accept
            std::array<std::uint8_t, 256> chunk{};
            std::string resp;
            for (int i = 0; i < 16; ++i)
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    as_bytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || n == 0)
                    break;
                resp.append(reinterpret_cast<const char *>(chunk.data()), n);
                if (resp.find("\r\n\r\n") != std::string::npos)
                    break;
            }
            if (resp.find("101") == std::string::npos)
                co_return error::bad_magic;
            const auto expected = compute_accept(key);
            if (resp.find("Sec-WebSocket-Accept: " + expected) == std::string::npos)
                co_return error::bad_auth;
            accept_ = expected;
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：解析 Upgrade 请求并回复 Accept
         * @param key 输出客户端 Sec-WebSocket-Key
         * @return 错误码；bad_magic = 非 Upgrade 请求
         */
        [[nodiscard]] auto read_handshake(std::string &key)
        -> net::awaitable<error>
        {
            std::array<std::uint8_t, 256> chunk{};
            std::string header;
            for (int i = 0; i < 16; ++i)
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    as_bytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || n == 0)
                    break;
                header.append(reinterpret_cast<const char *>(chunk.data()), n);
                if (header.find("\r\n\r\n") != std::string::npos)
                    break;
            }
            if (header.find("Upgrade: websocket") == std::string::npos)
                co_return error::bad_magic;

            const auto key_pos = header.find("Sec-WebSocket-Key: ");
            if (key_pos == std::string::npos)
                co_return error::bad_magic;
            const auto key_start = key_pos + 19;
            const auto key_end = header.find("\r\n", key_start);
            key = header.substr(key_start, key_end - key_start);

            const auto accept = compute_accept(key);
            std::string resp = "HTTP/1.1 101 Switching Protocols\r\n";
            resp += "Upgrade: websocket\r\n";
            resp += "Connection: Upgrade\r\n";
            resp += "Sec-WebSocket-Accept: " + accept + "\r\n";
            resp += "\r\n";
            if (co_await send_bytes(as_u8_span(resp)))
                co_return error::io_error;
            accept_ = accept;
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 透传读取（帧边界恢复后的裸流）
         * @details 简化：直接透传底层数据（帧编解码由上层负责）。
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
         * @brief 透传写入
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

        /**
         * @brief 获取 Sec-WebSocket-Accept（握手后有效）
         */
        [[nodiscard]] auto accept() const -> const std::string &
        {
            return accept_;
        }

    private:
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
        std::string accept_;              ///< Sec-WebSocket-Accept（握手后）
        bool handshaken_{false};          ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using shared_conn = std::shared_ptr<conn<>>;

    static_assert(psmtest::transmission_like<conn<>>);

} // namespace psmtest::ws
