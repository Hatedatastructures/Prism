/**
 * @file Dgram.hpp
 * @brief Hysteria2 UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层数据报传输（Unreliable，
 * 或任意包边界的传输）包装为 Hysteria2 逐帧编解码层。
 * 帧格式：[Kind 1B=0x02][SessionID 4B LE][PacketID 4B LE]
 *          [ATYP 1B][ADDR][PORT 2B BE][payload]。
 * 目标地址内嵌于帧内，Session/packet Id 由本对象自增维护。
 * @note 继承 Preview::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
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
#include <Preview/Protocols/Hysteria2/Codec.hpp>
#include <Preview/Protocols/Hysteria2/Types.hpp>

namespace Preview::Hysteria2
{

    /**
     * @class Dgram
     * @brief Hysteria2 UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层数据报传输的独占所有权，对外暴露包级 API
     * （AsyncSendTo / AsyncReceiveFrom），内部完成逐帧编解码
     * （Codec.hpp 纯函数）。由工厂（ConnectPacket /
     * AcceptPacket）创建。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission, public std::enable_shared_from_this<Dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Upstream 底层数据报传输（已 Connect/Bind，所有权移交）
         */
        explicit Dgram(
            SharedTransmission Upstream,
            const bool StandardWire = false)
            : NextLayer_(std::move(Upstream)), StandardWire_(StandardWire)
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
         * @brief 传输类型（数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param Destination 目标地址（帧内携带）
         * @param Payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(
            const Address &Destination,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            if (NextLayer_->TransportType() != Preview::Transmission::Type::Udp)
            {
                co_return Error::NotSupported;
            }
            if (StandardWire_)
            {
                if (!BuildReferenceUdp(Destination, Payload, TxWire_))
                {
                    co_return Error::BadAddress;
                }
            }
            else
            {
                const auto PacketId = PacketId_;
                BuildUdp(UdpFrameInput{SessionId_, PacketId, &Destination, Payload}, TxWire_);
                if (TxWire_.empty())
                {
                    co_return Error::BadAddress;
                }
                ++PacketId_;
            }
            std::size_t Done = 0;
            while (Done < TxWire_.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(std::span<const std::uint8_t>(TxWire_)).subspan(Done),
                    ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return Error::IoError;
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
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param Source 输出源地址（帧内目标）
         * @param Payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            Address &Source,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            if (NextLayer_->TransportType() != Preview::Transmission::Type::Udp)
            {
                co_return Error::NotSupported;
            }
            std::array<std::uint8_t, 65536> Datagram{};
            std::error_code ErrorCode;
            const auto N = co_await NextLayer_->async_read_some(
                AsBytes(std::span<std::uint8_t>(Datagram)), ErrorCode);
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (N > Datagram.size())
            {
                co_return Error::BadLength;
            }
            if (StandardWire_)
            {
                co_return ParseReferenceUdp(
                    std::span<const std::uint8_t>(Datagram.data(), N),
                    Source,
                    Payload);
            }
            Message Parsed{};
            std::size_t Consumed = 0;
            const auto ParseError = Parse(
                std::span<const std::uint8_t>(Datagram.data(), N),
                Parsed,
                Consumed);
            if (ParseError != Error::None || Parsed.Type != Message::Kind::Udp || Consumed != N)
            {
                if (ParseError != Error::None)
                {
                    co_return ParseError;
                }
                co_return Error::BadMessage;
            }
            Source = Parsed.dst;
            Payload.assign(
                reinterpret_cast<const std::uint8_t *>(Parsed.payload.data()),
                reinterpret_cast<const std::uint8_t *>(Parsed.payload.data()) + Parsed.payload.size());
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层数据报原样）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
        }

        /**
         * @brief 透传写入（底层数据报原样）
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
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
         * @brief 获取底层传输共享引用
         * @return 底层传输共享指针
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
        [[nodiscard]] auto DispatchToExecutor() -> Net::awaitable<void>
        {
            if (NextLayer_)
            {
                co_await Net::dispatch(NextLayer_->Executor(), Net::use_awaitable);
            }
        }

        static auto AppendVarint(typename Memory::template Buffer<std::uint8_t> &Output,
                                 const std::uint64_t Value) -> void
        {
            if (Value <= 63)
            {
                Output.push_back(static_cast<std::uint8_t>(Value));
            }
            else if (Value <= 16383)
            {
                Output.push_back(static_cast<std::uint8_t>((Value >> 8U) | 0x40U));
                Output.push_back(static_cast<std::uint8_t>(Value));
            }
            else if (Value <= 1073741823)
            {
                Output.push_back(static_cast<std::uint8_t>((Value >> 24U) | 0x80U));
                Output.push_back(static_cast<std::uint8_t>(Value >> 16U));
                Output.push_back(static_cast<std::uint8_t>(Value >> 8U));
                Output.push_back(static_cast<std::uint8_t>(Value));
            }
            else
            {
                for (std::size_t Index = 0; Index < 8; ++Index)
                {
                    const auto Shift = static_cast<unsigned>((7U - Index) * 8U);
                    std::uint8_t Prefix = 0;
                    if (Index == 0)
                    {
                        Prefix = 0xC0U;
                    }
                    Output.push_back(static_cast<std::uint8_t>((Value >> Shift) | Prefix));
                }
            }
        }

        [[nodiscard]] static auto ReadVarint(std::span<const std::uint8_t> Data, std::size_t &Offset,
                                             std::uint64_t &Value) -> bool
        {
            if (Offset >= Data.size())
            {
                return false;
            }
            const auto First = Data[Offset];
            const auto Length = std::size_t{1U} << (First >> 6U);
            if (Data.size() - Offset < Length)
            {
                return false;
            }
            Value = First & 0x3FU;
            for (std::size_t Index = 1; Index < Length; ++Index)
            {
                Value = (Value << 8U) | Data[Offset + Index];
            }
            Offset += Length;
            return true;
        }

        [[nodiscard]] static auto AddressText(const Address &AddressValue) -> std::string
        {
            if (AddressValue.Type == AddressType::Ipv6)
            {
                std::string Result{"["};
                Result += AddressValue.Host;
                Result += "]:";
                Result += std::to_string(AddressValue.Port);
                return Result;
            }
            std::string Result = AddressValue.Host;
            Result += ':';
            Result += std::to_string(AddressValue.Port);
            return Result;
        }

        [[nodiscard]] auto BuildReferenceUdp(
            const Address &Destination,
            std::span<const std::uint8_t> Payload,
            typename Memory::template Buffer<std::uint8_t> &Output) -> bool
        {
            if (Destination.Host.empty() ||
                (Destination.Type != AddressType::Ipv4 &&
                 Destination.Type != AddressType::Ipv6 &&
                 Destination.Type != AddressType::Domain))
            {
                Output.clear();
                return false;
            }
            const auto DestinationText = AddressText(Destination);
            if (DestinationText.empty() || DestinationText.size() > 2048)
            {
                Output.clear();
                return false;
            }
            Address ParsedAddress;
            if (!ParseEndpoint(DestinationText, ParsedAddress))
            {
                Output.clear();
                return false;
            }
            Output.clear();
            Output.reserve(8 + DestinationText.size() + Payload.size() + 8);
            const auto Packet = static_cast<std::uint16_t>(PacketId_);
            Output.push_back(0);
            Output.push_back(0);
            Output.push_back(0);
            Output.push_back(0);
            Output.push_back(static_cast<std::uint8_t>(Packet >> 8U));
            Output.push_back(static_cast<std::uint8_t>(Packet));
            Output.push_back(0);
            Output.push_back(1);
            AppendVarint(Output, DestinationText.size());
            Output.insert(Output.end(), DestinationText.begin(), DestinationText.end());
            Output.insert(Output.end(), Payload.begin(), Payload.end());
            ++PacketId_;
            return true;
        }

        [[nodiscard]] static auto ParseEndpoint(std::string_view Text, Address &Output) -> bool
        {
            std::string_view Host;
            std::string_view PortText;
            if (Text.starts_with('['))
            {
                const auto Close = Text.find(']');
                if (Close == std::string_view::npos || Close + 1 >= Text.size() || Text[Close + 1] != ':')
                {
                    return false;
                }
                Host = Text.substr(1, Close - 1);
                PortText = Text.substr(Close + 2);
                Output.Type = AddressType::Ipv6;
            }
            else
            {
                const auto Colon = Text.rfind(':');
                if (Colon == std::string_view::npos || Colon == 0)
                {
                    return false;
                }
                Host = Text.substr(0, Colon);
                PortText = Text.substr(Colon + 1);
                if (Host.find(':') == std::string_view::npos &&
                    Host.find_first_not_of("0123456789.") == std::string_view::npos)
                {
                    Output.Type = AddressType::Ipv4;
                }
                else
                {
                    Output.Type = AddressType::Domain;
                }
            }
            if (Host.empty())
            {
                return false;
            }
            if (Output.Type == AddressType::Ipv4)
            {
                std::array<std::uint8_t, 4> Bytes{};
                if (!Preview::Protocol::Common::ParseIpv4Text(Host, Bytes))
                {
                    return false;
                }
            }
            else if (Output.Type == AddressType::Ipv6)
            {
                boost::system::error_code ErrorCode;
                (void)Net::ip::make_address_v6(Host, ErrorCode);
                if (ErrorCode)
                {
                    return false;
                }
            }
            std::uint32_t Port = 0;
            const auto [End, ErrorCode] = std::from_chars(PortText.data(), PortText.data() + PortText.size(), Port);
            if (ErrorCode != std::errc{} || End != PortText.data() + PortText.size() || Port > 65535)
            {
                return false;
            }
            Output.Host.assign(Host.data(), Host.size());
            Output.Port = static_cast<std::uint16_t>(Port);
            return true;
        }

        [[nodiscard]] static auto ParseReferenceUdp(std::span<const std::uint8_t> Data, Address &Source,
                                                    std::vector<std::uint8_t> &Payload) -> Error
        {
            if (Data.size() < 8)
            {
                return Error::NeedMore;
            }
            if (Data[6] != 0 || Data[7] != 1)
            {
                return Error::BadMessage;
            }
            std::size_t Offset = 8;
            std::uint64_t DestinationLength = 0;
            if (!ReadVarint(Data, Offset, DestinationLength) || DestinationLength == 0 ||
                DestinationLength > 2048 || DestinationLength > Data.size() - Offset)
            {
                return Error::BadMessage;
            }
            const auto Destination = std::string_view(reinterpret_cast<const char *>(Data.data() + Offset),
                                                      static_cast<std::size_t>(DestinationLength));
            Offset += static_cast<std::size_t>(DestinationLength);
            if (!ParseEndpoint(Destination, Source))
            {
                return Error::BadAddress;
            }
            Payload.assign(Data.begin() + static_cast<std::ptrdiff_t>(Offset), Data.end());
            return Error::None;
        }

        /**
         * @brief 精确读取指定字节数
         * @param Dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Dst) -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Dst.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(Dst.subspan(Done)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return true;
                }
                if (N > Dst.size() - Done)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param AddressValue 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &AddressValue) -> Net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                AddressValue,
                [this](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
                {
                    return ReadExact(Buffer);
                });
        }

        SharedTransmission NextLayer_; ///< 底层数据报传输（独占所有权）
        std::uint32_t SessionId_{0};    ///< UDP 会话 ID（测试简化：固定 0）
        std::uint32_t PacketId_{0};     ///< UDP 包 ID（逐包自增）
        bool StandardWire_{false};      ///< QUIC provider 使用 sing-quic 标准数据报格式
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

    static_assert(Preview::TransmissionLike<Dgram<>>);

} // namespace Preview::Hysteria2
