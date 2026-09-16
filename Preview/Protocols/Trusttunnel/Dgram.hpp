/**
 * @file Dgram.hpp
 * @brief TrustTunnel UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层传输包装为 HTTP/2 数据帧承载的
 * 包连接（对齐 mihomo transport/trusttunnel ListenPacket）。
 * 帧格式：[DATA 帧头 9B][负载]（简化：测试库直接透传数据报，
 * 帧编解码由上层 HTTP/2 层负责）。
 * @note 继承 Preview::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Trusttunnel/Codec.hpp>
#include <Preview/Protocols/Trusttunnel/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
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
         * @param Upstream 底层传输（已握手，所有权移交）
         */
        explicit Dgram(SharedTransmission Upstream)
            : NextLayer_(std::move(Upstream))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return {};
            }
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
         * @param Host 目标主机
         * @param Port 目标端口
         * @param Payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(
            std::string_view Host,
            std::uint16_t Port,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            if (Host.size() > std::numeric_limits<std::uint8_t>::max())
            {
                co_return Error::BadLength;
            }
            // 简化：UDP 数据报带 1 字节长度 + 主机 + 2 字节端口 + 载荷透传
            std::vector<std::uint8_t> Wire;
            Wire.reserve(1 + Host.size() + 2 + Payload.size());
            Wire.push_back(static_cast<std::uint8_t>(Host.size()));
            Wire.insert(Wire.end(), Host.begin(), Host.end());
            Wire.push_back(static_cast<std::uint8_t>(Port >> 8));
            Wire.push_back(static_cast<std::uint8_t>(Port & 0xFF));
            Wire.insert(Wire.end(), Payload.begin(), Payload.end());
            std::size_t Done = 0;
            while (Done < Wire.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(std::span<const std::uint8_t>(Wire)).subspan(Done), ErrorCode);
                if (ErrorCode || N == 0)
                    co_return Error::IoError;
                if (N > Wire.size() - Done)
                    co_return Error::BadLength;
                Done += N;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param Host 输出源主机
         * @param Port 输出源端口
         * @param Payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            std::string &Host,
            std::uint16_t &Port,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Host.clear();
            Port = 0;
            Payload.clear();
            std::array<std::uint8_t, 1> HostLength{};
            std::size_t Done = 0;
            while (Done < HostLength.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(HostLength).subspan(Done)), ErrorCode);
                if (ErrorCode || N == 0)
                    co_return Error::UnexpectedEof;
                if (N > HostLength.size() - Done)
                    co_return Error::BadLength;
                Done += N;
            }
            std::vector<std::uint8_t> HostBuf(HostLength[0]);
            Done = 0;
            while (Done < HostBuf.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(HostBuf).subspan(Done)), ErrorCode);
                if (ErrorCode || N == 0)
                    co_return Error::UnexpectedEof;
                if (N > HostBuf.size() - Done)
                    co_return Error::BadLength;
                Done += N;
            }
            Host.assign(reinterpret_cast<const char *>(HostBuf.data()), HostBuf.size());
            std::array<std::uint8_t, 2> PortBuf{};
            Done = 0;
            while (Done < PortBuf.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(PortBuf).subspan(Done)), ErrorCode);
                if (ErrorCode || N == 0)
                    co_return Error::UnexpectedEof;
                if (N > PortBuf.size() - Done)
                    co_return Error::BadLength;
                Done += N;
            }
            Port = static_cast<std::uint16_t>(PortBuf[0]) << 8 | PortBuf[1];
            std::array<std::uint8_t, 512> Chunk{};
            std::error_code ErrorCode;
            const auto N = co_await NextLayer_->async_read_some(
                AsBytes(std::span<std::uint8_t>(Chunk)), ErrorCode);
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (N > Chunk.size())
                co_return Error::BadLength;
            Payload.assign(Chunk.begin(), Chunk.begin() + static_cast<std::ptrdiff_t>(N));
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层原样）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
        }

        /**
         * @brief 透传写入（底层原样）
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            co_return co_await NextLayer_->async_write_some(Buffer, ErrorCode);
        }

        /**
         * @brief 关闭底层传输
         */
        auto Close() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        auto Cancel() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Cancel();
            }
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
