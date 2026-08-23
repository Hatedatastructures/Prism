/**
 * @file conn.hpp
 * @brief Tuic 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 Tuic 连接：
 * 1. write_handshake / read_handshake：客户端发 connect 帧
 *    （目标地址）；服务端解析校验（简化：不做 UUID 认证）
 * 2. 隧道：async_read_some / async_write_some 透传 TCP 帧载荷
 * 3. UDP 数据面：async_send_datagram / async_receive_datagram
 *    逐帧编解码（codec.hpp 纯函数，packet 命令）
 * @note 与 tuic.hpp 工厂配对使用（服务端/客户端分离设计）
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
#include <utility>
#include <vector>

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/protocol/address.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/tuic/codec.hpp>
#include <common/protocols/tuic/types.hpp>

namespace preview::tuic
{

    /**
     * @class conn
     * @brief Tuic 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后通过
     * transmission 接口透传 TCP 帧载荷，或通过 async_send_datagram
     * / async_receive_datagram 收发 UDP 数据报。
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    class conn : public preview::transmission, public std::enable_shared_from_this<conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         * @param uuid 客户端 UUID（16 字节）
         */
        explicit conn(shared_transmission upstream, std::array<std::uint8_t, 16> uuid)
            : next_layer_(std::move(upstream)), uuid_(uuid)
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
         * @brief 客户端握手：发 connect 帧
         * @param target 目标地址
         * @return 错误码
         */
        [[nodiscard]] auto write_handshake(const address &target) -> net::awaitable<error>
        {
            message msg;
            msg.cmd = cmd_connect;
            msg.dst = target;
            const auto wire = build(msg);
            if (co_await send_bytes(wire))
            {
                co_return error::io_error;
            }
            target_ = target;
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：读 connect 帧
         * @return 错误码与解析的消息
         */
        [[nodiscard]] auto read_handshake() -> net::awaitable<std::pair<error, message>>
        {
            message msg;
            auto err = co_await read_frame(msg);
            if (err != error::none)
            {
                co_return std::pair{err, message{}};
            }
            if (msg.cmd != cmd_connect)
            {
                co_return std::pair{error::bad_message, message{}};
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
         * @brief 发送一个 UDP 数据报（packet 命令）
         * @param target 目标地址（帧内携带）
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_send_datagram(const address &target, std::span<const std::uint8_t> payload)
            -> net::awaitable<error>
        {
            if (!handshaken_)
            {
                co_return error::not_open;
            }
            message msg;
            msg.cmd = cmd_packet;
            msg.assoc_id = assoc_id_;
            msg.pkt_id = ++packet_id_;
            msg.dst = target;
            msg.payload.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
            const auto wire = build(msg);
            if (co_await send_bytes(wire))
            {
                co_return error::io_error;
            }
            co_return error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（packet 命令）
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
            if (msg.cmd != cmd_packet)
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
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto is_valid() const noexcept -> bool
        {
            return next_layer_ != nullptr && handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto underlying() noexcept -> shared_transmission
        {
            return next_layer_;
        }

        /**
         * @brief 获取会话级内存竞技场
         * @return 非拥有资源指针（供握手/解析的临时分配）
         * @note 分配的对象随 conn 存活，conn 析构时一次性回收
         */
        [[nodiscard]] auto arena() noexcept -> preview::memory::resource_pointer
        {
            return mem_.arena();
        }

    private:
        /**
         * @brief 读取一帧（Ver + Cmd + [id] + [地址] + [载荷]）
         * @param msg 输出消息
         * @return 错误码
         * @details 帧无长度字段：精确分段读取头部，剩余一次读为
         * 载荷（packet 命令）。
         */
        [[nodiscard]] auto read_frame(message &msg) -> net::awaitable<error>
        {
            std::array<std::uint8_t, 2> head{};
            if (co_await read_exact(std::span<std::uint8_t>(head)))
            {
                co_return error::unexpected_eof;
            }
            if (head[0] != protocol_version)
            {
                co_return error::bad_magic;
            }
            msg.cmd = head[1];
            if (msg.cmd == cmd_packet)
            {
                std::array<std::uint8_t, 8> ids{};
                if (co_await read_exact(std::span<std::uint8_t>(ids)))
                {
                    co_return error::unexpected_eof;
                }
                msg.assoc_id = static_cast<std::uint32_t>(ids[0]) | static_cast<std::uint32_t>(ids[1]) << 8 |
                               static_cast<std::uint32_t>(ids[2]) << 16 |
                               static_cast<std::uint32_t>(ids[3]) << 24;
                msg.pkt_id = static_cast<std::uint32_t>(ids[4]) | static_cast<std::uint32_t>(ids[5]) << 8 |
                             static_cast<std::uint32_t>(ids[6]) << 16 |
                             static_cast<std::uint32_t>(ids[7]) << 24;
            }
            if (msg.cmd == cmd_connect || msg.cmd == cmd_packet)
            {
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
            }
            if (msg.cmd == cmd_packet)
            {
                // 载荷：剩余一次读（帧边界约定）
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto n =
                    co_await next_layer_->async_read_some(as_bytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec)
                {
                    co_return error::io_error;
                }
                msg.payload.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            }
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
         * @note 转发层：统一实现见 protocol/common::read_address_body
         */
        [[nodiscard]] auto read_address_body(address &addr) -> net::awaitable<error>
        {
            return preview::protocol::common::read_address_body(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return read_exact(dst); });
        }

        shared_transmission next_layer_;      ///< 底层传输（独占所有权）
        std::array<std::uint8_t, 16> uuid_{}; ///< 客户端 UUID（凭据）
        address target_;                      ///< TCP 目标地址（握手后）
        message parsed_{};                    ///< 服务端握手解析结果
        std::uint32_t assoc_id_{0};           ///< UDP 关联 ID
        std::uint32_t packet_id_{0};          ///< UDP 包 ID（自增）
        bool handshaken_{false};              ///< 握手完成标志
        Memory mem_;     ///< 会话级内存竞技场（热路径零释放分配）
    };


    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn<>>;

    static_assert(preview::transmission_like<conn<>>);

} // namespace preview::tuic
