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

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Trusttunnel/Codec.hpp>
#include <preview/Protocols/Trusttunnel/Types.hpp>

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
            : NextLayer_(std::move(upstream))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 传输类型（TCP 承载数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
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
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(std::span<const std::uint8_t>(wire)).subspan(Done), ec);
                if (ec || N == 0)
                    co_return Error::IoError;
                Done += N;
            }
            co_return Error::None;
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
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(hlen).subspan(Done)), ec);
                if (ec || N == 0)
                    co_return Error::UnexpectedEof;
                Done += N;
            }
            std::vector<std::uint8_t> HostBuf(hlen[0]);
            Done = 0;
            while (Done < HostBuf.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(HostBuf).subspan(Done)), ec);
                if (ec || N == 0)
                    co_return Error::UnexpectedEof;
                Done += N;
            }
            host.assign(reinterpret_cast<const char *>(HostBuf.data()), HostBuf.size());
            std::array<std::uint8_t, 2> PortBuf{};
            Done = 0;
            while (Done < PortBuf.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(PortBuf).subspan(Done)), ec);
                if (ec || N == 0)
                    co_return Error::UnexpectedEof;
                Done += N;
            }
            port = static_cast<std::uint16_t>(PortBuf[0]) << 8 | PortBuf[1];
            std::array<std::uint8_t, 512> chunk{};
            std::error_code ec;
            const auto N = co_await NextLayer_->async_read_some(
                AsBytes(std::span<std::uint8_t>(chunk)), ec);
            if (ec)
                co_return Error::IoError;
            payload.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(N));
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入（底层原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                            std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            NextLayer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }

        /**
         * @brief 获取底层传输
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
        SharedTransmission NextLayer_; ///< 底层传输（独占所有权）
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram>;

    static_assert(Preview::TransmissionLike<Dgram>);

} // namespace Preview::Trusttunnel
