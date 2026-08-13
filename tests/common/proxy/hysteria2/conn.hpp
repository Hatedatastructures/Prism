/**
 * @file conn.hpp
 * @brief Hysteria2 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 Hysteria2 连接：
 * 1. write_handshake / read_handshake：客户端发认证帧（HTTP/3
 *    HEADERS 风格）与 TCP 目标帧；服务端解析校验（简化：不严格
 *    校验认证内容）
 * 2. 隧道：async_read_some / async_write_some 透传 TCP 帧载荷
 * 3. UDP 数据面：async_send_datagram / async_receive_datagram
 *    逐帧编解码（codec.hpp 纯函数），目标地址随帧携带
 * @note 与 hysteria2.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
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
#include <common/proxy/hysteria2/codec.hpp>
#include <common/proxy/hysteria2/types.hpp>

namespace psmtest::hysteria2
{

    /**
     * @class conn
     * @brief Hysteria2 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后通过
     * transmission 接口透传 TCP 帧载荷，或通过 async_send_datagram
     * / async_receive_datagram 收发 UDP 数据报。
     */
    class conn : public psmtest::transmission, public std::enable_shared_from_this<conn>
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
         * @brief 客户端握手：发认证帧 + TCP 目标帧
         * @param target 目标地址
         * @return 错误码
         * @details 认证帧（make_auth_request）后紧跟 TCP 帧
         * （目标 + 空载荷），对齐 sing-hysteria2 客户端行为。
         */
        [[nodiscard]] auto write_handshake(const address &target) -> net::awaitable<error>
        {
            const auto auth = make_auth_request(password_);
            if (co_await send_bytes(as_u8_span(auth)))
            {
                co_return error::io_error;
            }
            const auto tcp = build_tcp(target, {});
            if (co_await send_bytes(tcp))
            {
                co_return error::io_error;
            }
            target_ = target;
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：读认证帧（校验） + TCP 目标帧
         * @return 错误码与解析的消息
         * @details 读取认证帧（简化：仅校验 HEADERS 首字节 0x01），
         * 再读 TCP 目标帧解析地址与初始载荷。
         */
        [[nodiscard]] auto read_handshake() -> net::awaitable<std::pair<error, message>>
        {
            // 1. 认证帧：HEADERS 类型 0x01 + 1B 长度 + 头块
            std::array<std::uint8_t, 2> auth_head{};
            if (co_await read_exact(std::span<std::uint8_t>(auth_head)))
            {
                co_return std::pair{error::io_error, message{}};
            }
            if (auth_head[0] != 0x01)
            {
                co_return std::pair{error::bad_magic, message{}};
            }
            std::vector<std::uint8_t> auth_body(auth_head[1]);
            if (co_await read_exact(auth_body))
            {
                co_return std::pair{error::io_error, message{}};
            }
            const std::string auth(auth_body.begin(), auth_body.end());
            if (auth.find("Authorization: " + password_) == std::string::npos)
            {
                co_return std::pair{error::bad_auth, message{}};
            }

            // 2. TCP 目标帧
            message msg;
            auto err = co_await read_frame(msg);
            if (err != error::none)
            {
                co_return std::pair{err, message{}};
            }
            target_ = msg.dst;
            parsed_ = msg;
            handshaken_ = true;
            co_return std::pair{error::none, std::move(msg)};
        }

        /**
         * @brief 获取服务端握手解析的消息
         */
        [[nodiscard]] auto parsed() const -> const message &
        {
            return parsed_;
        }

        /**
         * @brief 发送一个 UDP 数据报（UDP 数据面）
         * @param target 目标地址（帧内携带）
         * @param payload 载荷
         * @return 错误码
         * @details 逐帧编解码（build_udp），session/packet id 递增。
         */
        [[nodiscard]] auto async_send_datagram(const address &target, std::span<const std::uint8_t> payload)
            -> net::awaitable<error>
        {
            if (!handshaken_)
            {
                co_return error::not_open;
            }
            const auto wire = build_udp(udp_frame_input{session_id_, ++packet_id_, &target, payload});
            co_return co_await send_bytes(wire) ? error::io_error : error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（UDP 数据面）
         * @param target 输出目标地址
         * @param payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_receive_datagram(address &target, std::vector<std::uint8_t> &payload)
            -> net::awaitable<error>
        {
            if (!handshaken_)
            {
                co_return error::not_open;
            }
            message msg;
            auto err = co_await read_frame(msg);
            if (err != error::none)
            {
                co_return err;
            }
            if (msg.type != message::kind::udp)
            {
                co_return error::bad_message;
            }
            target = msg.dst;
            payload.assign(msg.payload.begin(), msg.payload.end());
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
         * @brief 读取一帧（Kind + [id] + 地址 + 载荷）
         * @param msg 输出消息
         * @return 错误码
         * @details 帧无长度字段：精确分段读取头部（Kind/id/地址），
         * 剩余一次读为载荷。
         */
        [[nodiscard]] auto read_frame(message &msg) -> net::awaitable<error>
        {
            std::array<std::uint8_t, 1> kind{};
            if (co_await read_exact(std::span<std::uint8_t>(kind)))
            {
                co_return error::unexpected_eof;
            }
            msg.type = static_cast<message::kind>(kind[0]);
            if (msg.type == message::kind::udp)
            {
                std::array<std::uint8_t, 8> ids{};
                if (co_await read_exact(std::span<std::uint8_t>(ids)))
                {
                    co_return error::unexpected_eof;
                }

                msg.session_id =
                    static_cast<std::uint32_t>(ids[0]) | static_cast<std::uint32_t>(ids[1]) << 8 |
                    static_cast<std::uint32_t>(ids[2]) << 16 | static_cast<std::uint32_t>(ids[3]) << 24;
                msg.packet_id = static_cast<std::uint32_t>(ids[4]) | static_cast<std::uint32_t>(ids[5]) << 8 |
                                static_cast<std::uint32_t>(ids[6]) << 16 |
                                static_cast<std::uint32_t>(ids[7]) << 24;
            }
            // 地址体：ATYP(1) + ADDR + PORT(2)
            std::array<std::uint8_t, 1> atyp{};
            if (co_await read_exact(std::span<std::uint8_t>(atyp)))
            {
                co_return error::unexpected_eof;
            }
            msg.dst.type = static_cast<address_type>(atyp[0]);
            auto err = co_await read_address_body(msg.dst);
            if (err != error::none)
            {
                co_return err;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await read_exact(std::span<std::uint8_t>(port)))
            {
                co_return error::unexpected_eof;
            }
            msg.dst.port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];
            if (msg.type != message::kind::udp)
            {
                co_return error::none;
            }
            // 载荷：剩余一次读（帧边界由调用方约定）
            std::array<std::uint8_t, 512> chunk{};
            std::error_code ec;
            const auto n =
                co_await next_layer_->async_read_some(as_bytes(std::span<std::uint8_t>(chunk)), ec);
            if (ec)
            {
                co_return error::io_error;
            }
            msg.payload.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            co_return error::none;
        }

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
         * @brief 发送全部字节
         * @param data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto send_bytes(std::span<const std::uint8_t> data) const -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < data.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(as_bytes(data.subspan(done)), ec);
                if (ec)
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

        shared_transmission next_layer_; ///< 底层传输（独占所有权）
        std::string password_;           ///< 认证密码
        address target_;                 ///< TCP 目标地址（握手后）
        message parsed_{};               ///< 服务端握手解析结果
        std::uint32_t session_id_{0};    ///< UDP 会话 ID（自增）
        std::uint32_t packet_id_{0};     ///< UDP 包 ID（自增）
        bool handshaken_{false};         ///< 握手完成标志
    };

    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn>;

    static_assert(psmtest::transmission_like<conn>);

} // namespace psmtest::hysteria2
