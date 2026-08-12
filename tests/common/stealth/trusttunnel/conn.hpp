/**
 * @file conn.hpp
 * @brief TrustTunnel 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 TrustTunnel 连接（对齐 mihomo
 * transport/trusttunnel/client.go）：
 * 1. write_handshake：发送 HTTP/2 CONNECT 请求头（含 Basic Auth）
 * 2. read_handshake：服务端解析 CONNECT 请求并校验认证
 * 3. 数据面：HTTP/2 数据帧承载（测试库简化透传）
 * @note 与 trusttunnel.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/stealth/trusttunnel/codec.hpp>
#include <common/stealth/trusttunnel/types.hpp>

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

namespace psmtest::trusttunnel
{

    /**
     * @class conn
     * @brief TrustTunnel 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     */
    class conn : public psmtest::transmission,
                 public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         * @param user 认证用户名
         * @param pass 认证密码
         */
        explicit conn(shared_transmission upstream, std::string user, std::string pass)
            : next_layer_(std::move(upstream)), user_(std::move(user)), pass_(std::move(pass))
        {
        }

        /// @brief 获取执行器（委托底层传输）
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 客户端握手：发送 CONNECT 请求头
         * @param target 目标主机
         * @param port 目标端口
         * @return 错误码
         */
        [[nodiscard]] auto write_handshake(std::string_view target, std::uint16_t port)
            -> net::awaitable<error>
        {
            const auto auth = basic_auth(user_, pass_);
            std::string header;
            header.reserve(64 + target.size() + auth.size());
            header += "CONNECT " + std::string(target) + ":" + std::to_string(port) + " HTTP/2\r\n";
            header += "Proxy-Authorization: " + auth + "\r\n";
            header += "\r\n";
            if (co_await send_bytes(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(header.data()), header.size())))
                co_return error::io_error;
            target_ = std::string(target);
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：解析 CONNECT 请求并校验认证
         * @param target 输出目标主机
         * @return 错误码；bad_auth = 认证失败
         */
        [[nodiscard]] auto read_handshake(std::string &target) -> net::awaitable<error>
        {
            // 读取头块（简化：读到空行）
            std::array<std::uint8_t, 256> chunk{};
            std::string header;
            bool found_end = false;
            int loop_cnt = 0;
            for (int i = 0; i < 16; ++i)
            {
                loop_cnt = i + 1;
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    as_bytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || n == 0)
                    break;
                header.append(reinterpret_cast<const char *>(chunk.data()), n);
                if (header.find("\r\n\r\n") != std::string::npos)
                {
                    found_end = true;
                    break;
                }
            }
            if (!found_end)
                co_return error::bad_magic;
            if (header.find("CONNECT ") != 0)
                co_return error::bad_magic;

            // 解析目标与认证
            const auto first_line_end = header.find("\r\n");
            const auto target_line = header.substr(8, first_line_end - 8);
            const auto colon = target_line.find(':');
            if (colon != std::string::npos)
                target = target_line.substr(0, colon);
            else
                target = target_line;

            const auto auth_pos = header.find("Proxy-Authorization: ");
            if (auth_pos == std::string::npos)
                co_return error::bad_auth;
            const auto auth_start = auth_pos + 21;
            const auto auth_end = header.find("\r\n", auth_start);
            const auto auth = header.substr(auth_start, auth_end - auth_start);
            if (!verify_basic_auth(auth, user_, pass_))
                co_return error::bad_auth;

            target_ = target;
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
        std::string user_;                ///< 认证用户名
        std::string pass_;                ///< 认证密码
        std::string target_;              ///< CONNECT 目标（握手后）
        bool handshaken_{false};          ///< 握手完成标志
    };

    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn>;

    static_assert(psmtest::transmission_like<conn>);

} // namespace psmtest::trusttunnel
