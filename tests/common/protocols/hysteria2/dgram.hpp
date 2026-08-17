/**
 * @file dgram.hpp
 * @brief Hysteria2 UDP 包连接对象（transmission 装饰器）
 * @details UDP 数据面连接：将底层数据报传输（unreliable，
 * 或任意包边界的传输）包装为 Hysteria2 逐帧编解码层。
 * 帧格式：[Kind 1B=0x02][SessionID 4B LE][PacketID 4B LE]
 *          [ATYP 1B][ADDR][PORT 2B BE][payload]。
 * 目标地址内嵌于帧内，session/packet id 由本对象自增维护。
 * @note 继承 preview::transmission，构造函数传入底层传输（相当于
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
#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/hysteria2/codec.hpp>
#include <common/protocols/hysteria2/types.hpp>

namespace preview::hysteria2
{

    /**
     * @class dgram
     * @brief Hysteria2 UDP 包连接对象（transmission 装饰器）
     * @details 持有底层数据报传输的独占所有权，对外暴露包级 API
     * （async_send_to / async_receive_from），内部完成逐帧编解码
     * （codec.hpp 纯函数）。由工厂（connect_packet /
     * accept_packet）创建。
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    class dgram : public preview::transmission, public std::enable_shared_from_this<dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 底层数据报传输（已 connect/bind，所有权移交）
         */
        explicit dgram(shared_transmission upstream) : next_layer_(std::move(upstream))
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
         * @brief 传输类型（数据报）
         */
        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return type::udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param dest 目标地址（帧内携带）
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_send_to(const address &dest, std::span<const std::uint8_t> payload)
            -> net::awaitable<error>
        {
            build_udp(udp_frame_input{session_id_, ++packet_id_, &dest, payload}, tx_wire_);
            std::size_t done = 0;
            while (done < tx_wire_.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(
                    as_bytes(std::span<const std::uint8_t>(tx_wire_)).subspan(done), ec);
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
         * @param src 输出源地址（帧内目标）
         * @param payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_receive_from(address &src, std::vector<std::uint8_t> &payload)
            -> net::awaitable<error>
        {
            // 1. Kind + SessionID(4) + PacketID(4)
            std::array<std::uint8_t, 9> head{};
            if (co_await read_exact(std::span<std::uint8_t>(head)))
            {
                co_return error::unexpected_eof;
            }
            if (head[0] != static_cast<std::uint8_t>(message::kind::udp))
            {
                co_return error::bad_message;
            }

            // 2. ATYP + ADDR + PORT
            src.type = static_cast<address_type>(head[8]);
            auto err = co_await read_address_body(src);
            if (err != error::none)
            {
                co_return err;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await read_exact(std::span<std::uint8_t>(port)))
            {
                co_return error::unexpected_eof;
            }
            src.port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];

            // 3. 剩余为 payload（单次读取，帧边界约定）
            std::array<std::uint8_t, 512> chunk{};
            std::error_code ec;
            const auto n =
                co_await next_layer_->async_read_some(as_bytes(std::span<std::uint8_t>(chunk)), ec);
            if (ec)
            {
                co_return error::io_error;
            }
            if (n == 0)
            {
                co_return error::unexpected_eof;
            }
            payload.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            co_return error::none;
        }

        /**
         * @brief 透传读取（底层数据报原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 透传写入（底层数据报原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
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
        [[nodiscard]] auto next_layer() noexcept -> preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto next_layer() const noexcept -> const preview::transmission * override
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
         * @brief 获取底层传输
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

        shared_transmission next_layer_; ///< 底层数据报传输（独占所有权）
        std::uint32_t session_id_{0};    ///< UDP 会话 ID（自增）
        std::uint32_t packet_id_{0};     ///< UDP 包 ID（自增）
        Memory mem_;                     ///< 会话内存策略（arena，热路径零释放分配）
        typename Memory::template buffer<std::uint8_t> tx_wire_{mem_.arena()}; ///< 发送缓冲（arena 复用，热路径零分配）
    };

    /// 包连接共享指针
    using shared_dgram = std::shared_ptr<dgram<>>;

    static_assert(preview::transmission_like<dgram<>>);

} // namespace preview::hysteria2
