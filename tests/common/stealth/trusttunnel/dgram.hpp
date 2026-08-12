/**
 * @file dgram.hpp
 * @brief TrustTunnel UDP 包连接对象（transmission 装饰器）
 * @details UDP 数据面连接：将底层传输包装为 HTTP/2 数据帧承载的
 * 包连接（对齐 mihomo transport/trusttunnel ListenPacket）。
 * 帧格式：[DATA 帧头 9B][payload]（简化：测试库直接透传数据报，
 * 帧编解码由上层 HTTP/2 层负责）。
 * @note 继承 psmtest::transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 conn 的装饰器链模式。
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
#include <utility>
#include <vector>

namespace psmtest::trusttunnel
{

    /**
     * @class dgram
     * @brief TrustTunnel UDP 包连接对象（transmission 装饰器）
     * @details 持有底层传输的独占所有权，对外暴露包级 API
     * （async_send_to / async_receive_from）。
     */
    class dgram : public psmtest::transmission,
                  public std::enable_shared_from_this<dgram>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 底层传输（已握手，所有权移交）
         */
        explicit dgram(shared_transmission upstream)
            : next_layer_(std::move(upstream))
        {
        }

        /// @brief 获取执行器（委托底层传输）
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /// @brief 传输类型（TCP 承载数据报）
        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return type::udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param host 目标主机
         * @param port 目标端口
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_send_to(std::string_view host, std::uint16_t port,
                                         std::span<const std::uint8_t> payload)
        -> net::awaitable<error>
        {
            // 简化：UDP 数据报带 1 字节长度 + 主机 + 2 字节端口 + 载荷透传
            std::vector<std::uint8_t> wire;
            wire.reserve(1 + host.size() + 2 + payload.size());
            wire.push_back(static_cast<std::uint8_t>(host.size()));
            wire.insert(wire.end(), host.begin(), host.end());
            wire.push_back(static_cast<std::uint8_t>(port >> 8));
            wire.push_back(static_cast<std::uint8_t>(port & 0xFF));
            wire.insert(wire.end(), payload.begin(), payload.end());
            std::size_t done = 0;
            while (done < wire.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(
                    as_bytes(std::span<const std::uint8_t>(wire)).subspan(done), ec);
                if (ec)
                    co_return error::io_error;
                done += n;
            }
            co_return error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param host 输出源主机
         * @param port 输出源端口
         * @param payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_receive_from(std::string &host, std::uint16_t &port,
                                              std::vector<std::uint8_t> &payload)
        -> net::awaitable<error>
        {
            std::array<std::uint8_t, 1> hlen{};
            std::size_t done = 0;
            while (done < hlen.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    as_bytes(std::span<std::uint8_t>(hlen).subspan(done)), ec);
                if (ec || n == 0)
                    co_return error::unexpected_eof;
                done += n;
            }
            std::vector<std::uint8_t> host_buf(hlen[0]);
            done = 0;
            while (done < host_buf.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    as_bytes(std::span<std::uint8_t>(host_buf).subspan(done)), ec);
                if (ec || n == 0)
                    co_return error::unexpected_eof;
                done += n;
            }
            host.assign(reinterpret_cast<const char *>(host_buf.data()), host_buf.size());
            std::array<std::uint8_t, 2> port_buf{};
            done = 0;
            while (done < port_buf.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    as_bytes(std::span<std::uint8_t>(port_buf).subspan(done)), ec);
                if (ec || n == 0)
                    co_return error::unexpected_eof;
                done += n;
            }
            port = static_cast<std::uint16_t>(port_buf[0]) << 8 | port_buf[1];
            std::array<std::uint8_t, 512> chunk{};
            std::error_code ec;
            const auto n = co_await next_layer_->async_read_some(
                as_bytes(std::span<std::uint8_t>(chunk)), ec);
            if (ec)
                co_return error::io_error;
            payload.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            co_return error::none;
        }

        /// @brief 透传读取（底层原样）
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /// @brief 透传写入（底层原样）
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer,
                                            std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
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

        /// @brief 获取底层传输
        [[nodiscard]] auto stream() const noexcept -> shared_transmission
        {
            return next_layer_;
        }

    private:
        shared_transmission next_layer_; ///< 底层传输（独占所有权）
    };

    /// 包连接共享指针
    using shared_dgram = std::shared_ptr<dgram>;

    static_assert(psmtest::transmission_like<dgram>);

} // namespace psmtest::trusttunnel
