/**
 * @file Dgram.hpp
 * @brief TrustTunnel UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层传输包装为 HTTP/2 数据帧承载的
 * 包连接（对齐 mihomo transport/trusttunnel ListenPacket）。
 * 帧格式：[DATA 帧头 9B][payload]（简化：测试库直接透传数据报，
 * 帧编解码由上层 HTTP/2 层负责）。
 * @note 继承 Preview::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Trusttunnel/Codec.hpp>
#include <common/Protocols/Trusttunnel/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Preview::Trusttunnel
{

    /**
     * @class Dgram
     * @brief TrustTunnel UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层传输的独占所有权，对外暴露包级 API
     * （AsyncSendTo / AsyncReceiveFrom）。
     */
    class Dgram : public Preview::Transmission,
                  public std::enable_shared_from_this<Dgram>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 底层传输（已握手，所有权移交）
         */
        explicit Dgram(SharedTransmission upstream)
            : next_layer_(std::move(upstream))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return next_layer_->Executor();
        }

        /**
         * @brief 传输类型（TCP 承载数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param host 目标主机
         * @param port 目标端口
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(std::string_view host, std::uint16_t port,
                                         std::span<const std::uint8_t> payload)
        -> net::awaitable<Error>
        {
            // 简化：UDP 数据报带 1 字节长度 + 主机 + 2 字节端口 + 载荷透传
            std::vector<std::uint8_t> wire;
            wire.reserve(1 + host.size() + 2 + payload.size());
            wire.push_back(static_cast<std::uint8_t>(host.size()));
            wire.insert(wire.end(), host.begin(), host.end());
            wire.push_back(static_cast<std::uint8_t>(port >> 8));
            wire.push_back(static_cast<std::uint8_t>(port & 0xFF));
            wire.insert(wire.end(), payload.begin(), payload.end());
            std::size_t Done = 0;
            while (Done < wire.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncWriteSome(
                    AsBytes(std::span<const std::uint8_t>(wire)).subspan(Done), ec);
                if (ec)
                    co_return Error::io_error;
                Done += n;
            }
            co_return Error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param host 输出源主机
         * @param port 输出源端口
         * @param payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(std::string &host, std::uint16_t &port,
                                              std::vector<std::uint8_t> &payload)
        -> net::awaitable<Error>
        {
            std::array<std::uint8_t, 1> hlen{};
            std::size_t Done = 0;
            while (Done < hlen.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncReadSome(
                    AsBytes(std::span<std::uint8_t>(hlen).subspan(Done)), ec);
                if (ec || n == 0)
                    co_return Error::unexpected_eof;
                Done += n;
            }
            std::vector<std::uint8_t> host_buf(hlen[0]);
            Done = 0;
            while (Done < host_buf.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncReadSome(
                    AsBytes(std::span<std::uint8_t>(host_buf).subspan(Done)), ec);
                if (ec || n == 0)
                    co_return Error::unexpected_eof;
                Done += n;
            }
            host.assign(reinterpret_cast<const char *>(host_buf.data()), host_buf.size());
            std::array<std::uint8_t, 2> port_buf{};
            Done = 0;
            while (Done < port_buf.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncReadSome(
                    AsBytes(std::span<std::uint8_t>(port_buf).subspan(Done)), ec);
                if (ec || n == 0)
                    co_return Error::unexpected_eof;
                Done += n;
            }
            port = static_cast<std::uint16_t>(port_buf[0]) << 8 | port_buf[1];
            std::array<std::uint8_t, 512> chunk{};
            std::error_code ec;
            const auto n = co_await next_layer_->AsyncReadSome(
                AsBytes(std::span<std::uint8_t>(chunk)), ec);
            if (ec)
                co_return Error::io_error;
            payload.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            co_return Error::none;
        }

        /**
         * @brief 透传读取（底层原样）
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->AsyncReadSome(Buffer, ec);
        }

        /**
         * @brief 透传写入（底层原样）
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer,
                                            std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->AsyncWriteSome(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            next_layer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            next_layer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(next_layer_);
        }

        /**
         * @brief 获取底层传输
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return next_layer_;
        }

    private:
        SharedTransmission next_layer_; ///< 底层传输（独占所有权）
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram>;

    static_assert(Preview::TransmissionLike<Dgram>);

} // namespace Preview::Trusttunnel
