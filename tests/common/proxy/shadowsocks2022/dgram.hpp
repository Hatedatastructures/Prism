/**
 * @file dgram.hpp
 * @brief SS2022 UDP 包连接对象（transmission 装饰器）
 * @details UDP 数据面连接：将底层数据报传输（udp_transmission，
 * 或任意包边界的传输）包装为 SS2022（SIP022）逐包 AEAD 编解码层。
 * - 客户端：底层 udp_transmission connect(remote) 后，本类逐包加密发送
 * - 服务端：底层 udp_transmission bind(port) 后，本类逐包解密
 * 每个包独立加密（SeparateHeader 含 SessionID/PacketID，nonce 派生），
 * 目标地址内嵌于包内，无状态。编解码逻辑复用 codec.hpp 纯函数
 * （build_udp_packet / parse_udp_packet）。
 * @note 继承 psmtest::transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 conn 的装饰器链模式。
 * @note 对齐 mihomo adapter/outbound/shadowsocks.go：
 *          ListenPacketContext 创建真实 UDP socket + DialPacketConn
 *          （逐包 AEAD），UDPOverTCP 才是可选的 TCP 封装模式。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/shadowsocks2022/codec.hpp>
#include <common/proxy/shadowsocks2022/types.hpp>

namespace psmtest::shadowsocks2022
{

    namespace ss = psmtest::ss2022;

    /**
     * @class dgram
     * @brief SS2022 UDP 包连接对象（transmission 装饰器）
     * @details 持有底层数据报传输的独占所有权，对外暴露包级 API
     * （async_send_to / async_receive_from），内部完成逐包 AEAD
     * 编解码（codec.hpp 纯函数）。由工厂（connect_packet /
     * accept_packet）创建。
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    class dgram : public psmtest::transmission, public std::enable_shared_from_this<dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 底层数据报传输（已 connect/bind，所有权移交）
         * @param key 16 字节 UDP 密钥（PSK 派生）
         */
        explicit dgram(shared_transmission upstream, std::array<std::uint8_t, 16> key)
            : next_layer_(std::move(upstream)), key_(key)
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
         * @brief 发送一个 UDP 数据报（WriteTo 语义，逐包 AEAD）
         * @param dest 目标地址（内嵌于包）
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_send_to(const ss::address &dest, std::span<const std::uint8_t> payload)
            -> net::awaitable<error>
        {
            if (!ss::build_udp_packet(ss::udp_build_input{key_, ++packet_id_, &dest, payload}, tx_wire_))
            {
                co_return error::bad_length;
            }
            std::error_code ec;
            const auto n = co_await next_layer_->async_write_some(
                as_bytes(std::span<const std::uint8_t>(tx_wire_)), ec);
            co_return (ec || n != tx_wire_.size()) ? error::io_error : error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义，逐包 AEAD）
         * @param src 输出源地址（包内目标）
         * @param payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_receive_from(ss::address &src, std::vector<std::uint8_t> &payload)
            -> net::awaitable<error>
        {
            std::array<std::uint8_t, 64 * 1024> buf{};
            std::error_code ec;
            const auto n = co_await next_layer_->async_read_some(as_bytes(std::span<std::uint8_t>(buf)), ec);
            if (ec)
            {
                co_return error::io_error;
            }
            if (n == 0)
            {
                co_return error::unexpected_eof;
            }
            co_return ss::parse_udp_packet(
                ss::udp_parse_input{key_, std::span<const std::uint8_t>(buf.data(), n), &src, &payload});
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
         * @brief 获取底层传输
         */
        [[nodiscard]] auto stream() const noexcept -> shared_transmission
        {
            return next_layer_;
        }

    private:
        shared_transmission next_layer_;   ///< 底层数据报传输（独占所有权）
        std::array<std::uint8_t, 16> key_; ///< UDP 会话密钥（PSK 派生）
        std::uint64_t packet_id_{0};       ///< 包序号（自增，nonce 派生）
        Memory mem_;                       ///< 会话内存策略（arena，热路径零释放分配）
        typename Memory::template buffer<std::uint8_t> tx_wire_{mem_.arena()}; ///< 发送缓冲（arena 复用，热路径零分配）
    };

    /// 包连接共享指针
    using shared_dgram = std::shared_ptr<dgram<>>;

} // namespace psmtest::shadowsocks2022
