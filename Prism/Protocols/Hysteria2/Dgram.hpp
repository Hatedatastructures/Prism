/**
 * @file Dgram.hpp
 * @brief Hysteria2 UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层数据报传输（Unreliable，
 * 或任意包边界的传输）包装为 Hysteria2 逐帧编解码层。
 * 内部模式使用自有带类型帧；QUIC 模式使用 Hysteria2 UDPMessage，按 QUIC
 * datagram 上限分片，并按 Session/Packet ID 重组。目标地址随每个 UDP 消息携带。
 * @note 继承 Prism::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Common/IoBridge.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Hysteria2/Codec.hpp>
#include <Prism/Protocols/Hysteria2/Detail/DatagramFragments.hpp>
#include <Prism/Protocols/Hysteria2/Types.hpp>

namespace Prism::Hysteria2
{

    /**
     * @class Dgram
     * @brief Hysteria2 UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层数据报传输的独占所有权，对外暴露包级 API
     * （AsyncSendTo / AsyncReceiveFrom），内部完成逐包编解码与 Hysteria2
     * UDP 分片重组。由工厂（ConnectPacket /
     * AcceptPacket）创建。
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Dgram : public Prism::Transmission
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Upstream 底层数据报传输（已 Connect/Bind，所有权移交）
         */
        explicit Dgram(
            SharedTransmission Upstream,
            const bool StandardWire = false)
            : Prism::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Upstream)), StandardWire_(StandardWire)
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Prism::Transmission::Executor();
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
            if (NextLayer_->TransportType() != Prism::Transmission::Type::Udp)
            {
                co_return Error::Unsupported;
            }
            if (StandardWire_)
            {
                if (Destination.Host.empty() ||
                    (Destination.Type != AddressType::Ipv4 &&
                     Destination.Type != AddressType::Ipv6 &&
                     Destination.Type != AddressType::Domain))
                {
                    co_return Error::BadAddress;
                }
                const auto DestinationText = AddressText(Destination);
                if (DestinationText.empty() || DestinationText.size() > 2048U)
                    co_return Error::BadAddress;
                Address ParsedDestination;
                if (!ParseEndpoint(DestinationText, ParsedDestination))
                {
                    co_return Error::BadAddress;
                }
                if (Payload.size() > Detail::MaxUdpPayloadSize)
                {
                    co_return Error::BadLength;
                }
                const auto Maximum = Detail::MaxReferenceUdpFragmentPayload(
                    DestinationText.size());
                if (!Maximum) co_return Error::BadLength;
                const auto FragmentCount = Payload.empty() ? 1U :
                    (Payload.size() + *Maximum - 1U) / *Maximum;
                if (FragmentCount == 0U || FragmentCount > 255U)
                    co_return Error::BadLength;
                const auto Packet = static_cast<std::uint16_t>(PacketId_++);
                for (std::size_t Index = 0; Index < FragmentCount; ++Index)
                {
                    const auto Offset = Index * *Maximum;
                    const auto Count = (std::min)(*Maximum, Payload.size() - Offset);
                    const Detail::ReferenceUdpBuildInput Input{
                        SessionId_, Packet, static_cast<std::uint8_t>(Index),
                        static_cast<std::uint8_t>(FragmentCount), DestinationText,
                        Payload.subspan(Offset, Count)};
                    if (!Detail::BuildReferenceUdpFragment(Input, TxWire_))
                        co_return Error::BadLength;
                    const auto Sent = co_await SendWire();
                    if (Sent != Error::None) co_return Sent;
                }
                co_return Error::None;
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
            co_return co_await SendWire();
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
            if (NextLayer_->TransportType() != Prism::Transmission::Type::Udp)
            {
                co_return Error::Unsupported;
            }
            while (true)
            {
                std::array<std::uint8_t, 65536> Datagram{};
                const auto Part = co_await NextLayer_->ReadSome(
                    AsBytes(std::span<std::uint8_t>(Datagram)));
                const auto N = Part.Bytes;
                if (Part.Failure.Failed())
                {
                    if (Part.Failure.Code == Prism::Fault::Code::Eof)
                        co_return Error::UnexpectedEof;
                    co_return Error::IoError;
                }
                if (N == 0) co_return Error::UnexpectedEof;
                if (N > Datagram.size()) co_return Error::BadLength;
                const auto Data = std::span<const std::uint8_t>(Datagram.data(), N);
                if (StandardWire_)
                {
                    const auto Fragment = Detail::ParseReferenceUdpFragment(Data);
                    if (!Fragment) co_return Fragment.error();
                    auto Packet = Reassembler_.Accept(*Fragment);
                    if (!Packet) co_return Packet.error();
                    if (!Packet->has_value()) continue;
                    auto Complete = std::move(**Packet);
                    if (!ParseEndpoint(Complete.Address, Source))
                        co_return Error::BadAddress;
                    SessionId_ = Complete.SessionId;
                    Payload = std::move(Complete.Payload);
                    co_return Error::None;
                }
                Message Parsed{};
                std::size_t Consumed = 0;
                const auto ParseError = Parse(Data, Parsed, Consumed);
                if (ParseError != Error::None || Parsed.Type != Message::Kind::Udp ||
                    Consumed != N)
                {
                    if (ParseError != Error::None) co_return ParseError;
                    co_return Error::BadMessage;
                }
                Source = Parsed.dst;
                Payload.assign(
                    reinterpret_cast<const std::uint8_t *>(Parsed.payload.data()),
                    reinterpret_cast<const std::uint8_t *>(Parsed.payload.data()) +
                        Parsed.payload.size());
                co_return Error::None;
            }
        }

        /** @brief 透传读取（底层数据报原样）；executor 与原域一致。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Protocols::StartPartialRead(
                Prism::Protocols::PartialReadInput<Dgram>{Owner(), Buffer, Executor()},
                std::move(Handler));
        }

        /** @brief 透传写入（底层数据报原样）。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Protocols::StartPartialWrite(
                Prism::Protocols::PartialWriteInput<Dgram>{Owner(), Buffer, Executor()},
                std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层数据报载体；反向读取仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Close();
        }

        /** @brief 可重复取消底层挂起操作；不宣称已经关闭。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Cancel();
        }

        /** @brief 一次部分读写的借用参数；只在本类与前门之间传递。 */
        struct PartialArgs final
        {
            bool IsWrite{false};
            std::span<std::byte> Read;
            std::span<const std::byte> Write;
        };

        /** @brief 数据面部分读实现，由正式前门复用。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            return Partial(PartialArgs{false, Buffer, {}});
        }

        /** @brief 数据面部分写实现，由正式前门复用；保留底层短写事实。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            return Partial(PartialArgs{true, {}, Buffer});
        }

        /** @brief 数据面部分读写实现；原样保留底层字节数与 typed failure。 */
        [[nodiscard]] auto Partial(PartialArgs Args) -> Net::awaitable<Prism::IoResult>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                co_return Prism::IoResult{
                    0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))};
            }
            if (Args.IsWrite)
            {
                co_return co_await NextLayer_->WriteSome(Args.Write);
            }
            co_return co_await NextLayer_->ReadSome(Args.Read);
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
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
        /** @brief 完成交付前的 owner 借用；存活由本次传输预约与调用者共同保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<Dgram>
        {
            return std::static_pointer_cast<Dgram>(Transmission::shared_from_this());
        }

        [[nodiscard]] auto DispatchToExecutor() -> Net::awaitable<void>
        {
            if (NextLayer_)
            {
                co_await Net::dispatch(NextLayer_->Executor(), Net::use_awaitable);
            }
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

        [[nodiscard]] auto SendWire() -> Net::awaitable<Error>
        {
            const auto Part = co_await NextLayer_->WriteSome(
                AsBytes(std::span<const std::uint8_t>(TxWire_)));
            if (Part.Bytes > TxWire_.size()) co_return Error::BadLength;
            if (Part.Failure.Failed() || Part.Bytes != TxWire_.size())
                co_return Error::IoError;
            co_return Error::None;
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
                if (!Prism::Protocol::Common::ParseIpv4Text(Host, Bytes))
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

        SharedTransmission NextLayer_; ///< 底层数据报传输（独占所有权）
        std::uint32_t SessionId_{0};    ///< 最近入站 UDP 关联 ID；响应沿同一关联返回。
        std::uint32_t PacketId_{0};     ///< UDP 包 ID（逐包自增）
        bool StandardWire_{false};      ///< QUIC provider 使用 Hysteria2 UDPMessage wire。
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
        Detail::ReferenceUdpFragmentReassembler Reassembler_;
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

    static_assert(Prism::TransmissionLike<Dgram<>>);

} // namespace Prism::Hysteria2
