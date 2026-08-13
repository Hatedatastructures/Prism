/**
 * @file dgram.hpp
 * @brief Trojan UDP 包连接对象（transmission 装饰器）
 * @details UDP 数据面连接：将底层流连接（trojan::conn，同一条 TCP，
 * 不另开底层连接）包装为包级 API（async_send_to / async_receive_from），
 * 内部完成 UDP 帧编解码与剩余包缓冲。
 * 帧格式：[ATYP][ADDR][PORT 2B BE][LEN 2B BE][CRLF][payload]。
 * @note 对齐 mihomo transport/trojan.PacketConn：包连接是独立类型，
 *          嵌入底层流连接，仅提供包语义（net.PacketConn 对应物）。
 * @note 继承 psmtest::transmission，构造函数传入底层流连接（相当于
 * socket 收发的持有者），对齐 conn 的装饰器链模式。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/trojan/codec.hpp>
#include <common/proxy/trojan/types.hpp>

namespace psmtest::trojan
{

    /**
     * @class dgram
     * @brief Trojan UDP 包连接对象（transmission 装饰器）
     * @details 持有底层流连接（trojan::conn，已握手）的独占所有权，
     * 对外暴露包级 API（async_send_to / async_receive_from），内部
     * 完成 UDP 帧编解码。由工厂（connect_packet / accept_packet）创建。
     */
    class dgram : public psmtest::transmission, public std::enable_shared_from_this<dgram>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param stream 底层流连接（已握手，所有权移交）
         */
        explicit dgram(shared_transmission stream) : next_layer_(std::move(stream))
        {
        }

        /**
         * @brief 获取执行器（委托底层流连接）
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 传输类型（经底层委托，TCP 承载数据报）
         */
        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return type::udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param dest 目标地址
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_send_to(const address &dest, std::span<const std::uint8_t> payload)
            -> net::awaitable<error>
        {
            const auto wire = build_udp_pkt(dest, payload);
            std::size_t done = 0;
            while (done < wire.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(as_bytes(wire).subspan(done), ec);
                if (ec)
                {
                    co_return error::io_error;
                }
                done += n;
            }
            co_return error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param src 输出源地址
         * @param payload 输出载荷
         * @return 错误码
         * @details 经底层流连接的预读缓冲精确分段读取完整帧。
         */
        [[nodiscard]] auto async_receive_from(address &src, std::vector<std::uint8_t> &payload)
            -> net::awaitable<error>
        {
            // 1. 读取地址体（ATYP + ADDR + PORT 2B BE）
            std::array<std::uint8_t, 1> atyp{};
            if (co_await read_exact(std::span<std::uint8_t>(atyp)))
            {
                co_return error::io_error;
            }
            src.type = static_cast<address_type>(atyp[0]);
            auto err = co_await read_address_body(src);
            if (err != error::none)
            {
                co_return err;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await read_exact(std::span<std::uint8_t>(port)))
            {
                co_return error::io_error;
            }
            src.port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];

            // 2. 读取头部：LEN(2 BE) + CRLF(2)
            std::array<std::uint8_t, 4> head{};
            if (co_await read_exact(std::span<std::uint8_t>(head)))
            {
                co_return error::io_error;
            }
            if (head[2] != '\r' || head[3] != '\n')
            {
                co_return error::bad_magic;
            }
            const auto len = static_cast<std::size_t>(head[0]) << 8 | head[1];

            // 3. 读取载荷
            payload.resize(len);
            if (len > 0 && co_await read_exact(payload))
            {
                co_return error::io_error;
            }
            co_return error::none;
        }

        /**
         * @brief 透传读取（底层流原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 透传写入（底层流原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭底层流连接
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
         * @brief 获取底层流连接
         */
        [[nodiscard]] auto stream() const noexcept -> shared_transmission
        {
            return next_layer_;
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
                {
                    co_return true;
                }
                done += n;
            }
            co_return false;
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param addr 输出地址
         * @return 错误码
         */
        [[nodiscard]] auto read_address_body(address &addr) -> net::awaitable<error>
        {
            switch (addr.type)
            {
            case address_type::ipv4: {
                std::array<std::uint8_t, 4> ip{};
                if (co_await read_exact(std::span<std::uint8_t>(ip)))
                {
                    co_return error::io_error;
                }
                std::array<char, 16> buf{};
                std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                addr.host = buf.data();
                break;
            }
            case address_type::ipv6: {
                std::array<std::uint8_t, 16> ip{};
                if (co_await read_exact(std::span<std::uint8_t>(ip)))
                {
                    co_return error::io_error;
                }
                addr.host.assign(reinterpret_cast<const char *>(ip.data()), 16);
                break;
            }
            case address_type::domain: {
                std::array<std::uint8_t, 1> len{};
                if (co_await read_exact(std::span<std::uint8_t>(len)))
                {
                    co_return error::io_error;
                }
                std::vector<std::uint8_t> host(len[0]);
                if (co_await read_exact(host))
                {
                    co_return error::io_error;
                }
                addr.host.assign(reinterpret_cast<const char *>(host.data()), host.size());
                break;
            }
            default: co_return error::bad_message;
            }
            co_return error::none;
        }

        shared_transmission next_layer_; ///< 底层流连接（嵌入，同一条 TCP）
    };

    /// 包连接共享指针
    using shared_dgram = std::shared_ptr<dgram>;

} // namespace psmtest::trojan
