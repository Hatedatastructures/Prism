/**
 * @file Dgram.hpp
 * @brief VLESS UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层流连接（Vless::Conn，同一条 TCP，
 * 不另开底层连接）包装为包级 API（AsyncSendTo / AsyncReceiveFrom）。
 * 标准工厂模式使用握手目标地址和 [LEN 2B BE][payload] 分帧；
 * 直接构造仍保留旧的 [ATYP][ADDR][PORT 2B BE][payload] 兼容模式。
 * @note 继承 Preview::Transmission，构造函数传入底层流连接（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    namespace Net = boost::asio;

    /**
     * @class Dgram
     * @brief VLESS UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层流连接（Vless::Conn，已握手）的独占所有权，
     * 对外暴露包级 API（AsyncSendTo / AsyncReceiveFrom）。
     * 由工厂（ConnectPacket / AcceptPacket）创建。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission, public std::enable_shared_from_this<Dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Stream 底层流连接（已握手，所有权移交）
         */
        explicit Dgram(SharedTransmission Stream) : NextLayer_(std::move(Stream))
        {
        }

        /**
         * @brief 构造标准 VLESS UDP 包连接
         * @param Stream 已完成 VLESS UDP 握手的流连接
         * @param Target 握手时协商的固定目标地址
         * @param StandardWire 是否使用标准长度分帧
         */
        Dgram(SharedTransmission Stream, Address Target, bool StandardWire)
            : NextLayer_(std::move(Stream)), Target_(std::move(Target)), StandardWire_(StandardWire)
        {
        }

        /**
         * @brief 获取执行器（委托底层流连接）
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
         * @brief 传输类型（经底层委托，TCP 承载数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 发送一个 UDP 帧（WriteTo 语义）
         * @param Target 目标地址
         * @param Payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(
            const Address &Target,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            if (StandardWire_)
            {
                if (Payload.size() > 0xFFFF)
                {
                    co_return Error::BadLength;
                }
                TxWire_.clear();
                TxWire_.resize(2 + Payload.size());
                TxWire_[0] = static_cast<std::uint8_t>(Payload.size() >> 8);
                TxWire_[1] = static_cast<std::uint8_t>(Payload.size() & 0xFF);
                std::copy(Payload.begin(), Payload.end(), TxWire_.begin() + 2);
            }
            else
            {
                if (NextLayer_->TransportType() != Preview::Transmission::Type::Udp)
                {
                    co_return Error::NotSupported;
                }
                BuildUdpPkt(Target, Payload, TxWire_);
                if (TxWire_.empty())
                {
                    co_return Error::BadAddress;
                }
            }
            std::size_t Done = 0;
            while (Done < TxWire_.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(std::span<const std::uint8_t>(TxWire_)).subspan(Done), ErrorCode);
                if (ErrorCode)
                {
                    co_return Error::IoError;
                }
                if (N == 0)
                {
                    co_return Error::BrokenPipe; // 底层零字节写入，防死循环
                }
                if (N > TxWire_.size() - Done)
                {
                    co_return Error::BadLength;
                }
                Done += N;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 帧（ReadFrom 语义）
         * @param Source 输出源地址
         * @param Payload 输出载荷
         * @return 错误码
         * @details 精确分段读取地址头（ATYP + ADDR + PORT），剩余
         * 字节为完整 payload（无长度帧）。
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            Address &Source,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            if (StandardWire_)
            {
                std::array<std::uint8_t, 2> Length{};
                const auto LengthError = co_await ReadExact(std::span<std::uint8_t>(Length));
                if (LengthError != Error::None)
                {
                    co_return LengthError;
                }
                const auto Size = static_cast<std::size_t>(Length[0]) << 8 | Length[1];
                Payload.resize(Size);
                if (Size > 0)
                {
                    const auto PayloadError = co_await ReadExact(std::span<std::uint8_t>(Payload));
                    if (PayloadError != Error::None)
                    {
                        co_return PayloadError;
                    }
                }
                Source = Target_;
                co_return Error::None;
            }
            if (NextLayer_->TransportType() != Preview::Transmission::Type::Udp)
            {
                co_return Error::NotSupported;
            }
            // 1. ATYP + ADDR + PORT
            std::array<std::uint8_t, 1> AddressTypeByte{};
            const auto AtypError = co_await ReadExact(std::span<std::uint8_t>(AddressTypeByte));
            if (AtypError != Error::None)
            {
                co_return AtypError;
            }
            Source.Type = static_cast<AddressType>(AddressTypeByte[0]);
            const auto AddressError = co_await ReadAddressBody(Source);
            if (AddressError != Error::None)
            {
                co_return AddressError;
            }
            if (Source.Type == AddressType::Domain && Source.Host.empty())
            {
                co_return Error::BadMessage;
            }
            std::array<std::uint8_t, 2> Port{};
            const auto PortError = co_await ReadExact(std::span<std::uint8_t>(Port));
            if (PortError != Error::None)
            {
                co_return PortError;
            }
            Source.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];

            // 2. 剩余为 payload（单次读取）
            std::array<std::uint8_t, 512> Chunk{};
            std::error_code ErrorCode;
            const auto N =
                co_await NextLayer_->async_read_some(AsBytes(std::span<std::uint8_t>(Chunk)), ErrorCode);
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (N > Chunk.size())
            {
                co_return Error::BadLength;
            }
            Payload.assign(Chunk.begin(), Chunk.begin() + static_cast<std::ptrdiff_t>(N));
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层流原样）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
        }

        /**
         * @brief 透传写入（底层流原样）
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ErrorCode);
        }

        /**
         * @brief 关闭底层流连接
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
         * @brief 获取底层流连接
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
        /**
         * @brief 精确读取指定字节数
         * @param Buffer 目标缓冲区
         * @return 错误码；None 表示完整读取，BadLength 表示底层违反窗口契约
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<Error>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                if (!NextLayer_)
                {
                    co_return Error::NotOpen;
                }
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(Buffer.subspan(Done)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return Error::IoError;
                }
                if (N > Buffer.size() - Done)
                {
                    co_return Error::BadLength;
                }
                Done += N;
            }
            co_return Error::None;
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param Output 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &Output) -> Net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                Output,
                [this](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
                {
                    co_return (co_await ReadExact(Buffer)) != Error::None;
                });
        }

        SharedTransmission NextLayer_; ///< 底层流连接（嵌入，同一条 TCP）
        Address Target_{};              ///< 标准 VLESS UDP 握手协商的固定目标
        bool StandardWire_{false};      ///< 是否使用标准长度分帧
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

} // namespace Preview::Vless
