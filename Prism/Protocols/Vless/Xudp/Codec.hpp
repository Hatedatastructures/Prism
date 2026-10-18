/**
 * @file VlessXudp.hpp
 * @brief VLESS XUDP（CommandMux）数据面解析与 UDP relay
 * @details 对齐 metacubex/sing-vmess v0.2.5 `xudp.go` / `mux.go` 的真实 wire：
 *          - 帧头 [2B Length][2B SessionId][1B Status][1B Option]
 *          - Length = 4 + body；body = [Network 1B][port-first AddrPort][globalID?]
 *          - payload 长度位于 body 之后，独立 2B 大端
 *          - 地址族：IPv4=0x01 / Fqdn=0x02 / IPv6=0x03；端口先于地址族字节
 *          - New 帧携带目标；Keep 短帧（Length=4）沿用会话已存目标
 *          - OptionError 表示远端关闭；OptionData 未置位表示空载荷控制帧
 * @note 回包帧使用长格式（network + 源地址），与 sing 服务端 writePacketFrame 对齐。
 */

#pragma once
#include <optional>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Vless::Xudp
{

    namespace Net = boost::asio;

    /// XUDP 帧状态（对齐 sing-vmess Status* 常量）
    enum class Status : std::uint8_t
    {
        New = 1,
        Keep = 2,
        End = 3,
        KeepAlive = 4,
    };

    /// 帧选项位（对齐 sing-vmess Option* 常量）
    inline constexpr std::uint8_t OptionData = 0x01U;
    inline constexpr std::uint8_t OptionError = 0x02U;
    /// XUDP 网络类型：UDP（对齐 sing-vmess NetworkUDP）
    inline constexpr std::uint8_t NetworkUdp = 0x02U;
    /// 地址族（对齐 sing-vmess AddressSerializer 映射）
    inline constexpr std::uint8_t FamilyIpv4 = 0x01U;
    inline constexpr std::uint8_t FamilyFqdn = 0x02U;
    inline constexpr std::uint8_t FamilyIpv6 = 0x03U;
    /// 单包最大载荷（UDP 上限）
    inline constexpr std::size_t MaxDatagram = 65535U;
    /// 上游回包等待上限（避免静默上游长期占用会话）
    inline constexpr auto ResponseTimeout = std::chrono::seconds(5);

    /**
     * @struct Frame
     * @brief 解析后的 XUDP 帧
     */
    struct Frame final
    {
        std::uint16_t SessionId{0};
        Status StatusValue{Status::Keep};
        bool HasTarget{false};
        Prism::Network::Target Target;
        std::vector<std::uint8_t> Payload;
    };

    /**
     * @brief 解析 port-first 地址（[Port 2B BE][Family 1B][Addr body]）
     * @param Data 帧体
     * @param Offset 读写偏移（解析成功后前移到地址末尾）
     * @param Host 输出主机（IPv4 点分 / Fqdn / IPv6 压缩文本）
     * @param Port 输出端口
     * @return 解析成功返回 true
     * @note 允许调用方在地址之后保留 globalID 等尾随字节。
     */
    struct Address final { Prism::Network::Target Target; std::size_t Consumed{0}; };
    /** @brief 借用本帧 port-first 字节，返回拥有目标与准确 Consumed；不足/非法返回空，不执行 I/O。 */
    [[nodiscard]] inline auto ReadAddress(std::span<const std::uint8_t> Data) -> std::optional<Address>
    {
        Address Result;
        Result.Target.Route = Prism::Network::RouteKind::Forward;
        std::size_t Offset=0;
        auto& Host=Result.Target.Host;
        auto& Port=Result.Target.Port;
        if (Data.size() - Offset < 2U)
        {
            return std::nullopt;
        }
        Port = static_cast<std::uint16_t>(Data[Offset] << 8U | Data[Offset + 1U]);
        Offset += 2U;
        if (Offset >= Data.size())
        {
            return std::nullopt;
        }
        const auto Family = Data[Offset++];
        if (Family == FamilyIpv4)
        {
            if (Data.size() - Offset < 4U)
            {
                return std::nullopt;
            }
            Prism::Network::Ipv4Bytes Bytes;
            std::copy_n(Data.begin() + static_cast<std::ptrdiff_t>(Offset), 4U, Bytes.Bytes.begin());
            Host = Prism::Network::Host(Bytes);
            Offset += 4U;
            Result.Consumed = Offset; return Result;
        }
        if (Family == FamilyFqdn)
        {
            if (Offset >= Data.size())
            {
                return std::nullopt;
            }
            const auto Length = static_cast<std::size_t>(Data[Offset++]);
            if (Data.size() - Offset < Length)
            {
                return std::nullopt;
            }
            auto Domain = Prism::Network::DecodeHost(Prism::Network::HostEncoding::Domain,
                {reinterpret_cast<const char *>(Data.data() + Offset), Length});
            if (!Domain) return std::nullopt;
            Host = std::move(*Domain);
            Offset += Length;
            Result.Consumed = Offset; return Result;
        }
        if (Family == FamilyIpv6)
        {
            if (Data.size() - Offset < 16U)
            {
                return std::nullopt;
            }
            Net::ip::address_v6::bytes_type Bytes{};
            std::copy_n(Data.begin() + static_cast<std::ptrdiff_t>(Offset), 16U, Bytes.begin());
            Host = Prism::Network::Host(Prism::Network::Ipv6Bytes{Bytes});
            Offset += 16U;
            Result.Consumed = Offset; return Result;
        }
        return std::nullopt;

    }

    [[nodiscard]] inline auto ReadFrame(Prism::SharedTransmission Inbound)
        -> Net::awaitable<std::expected<Frame, Prism::Fault::Failure>>
    {
        if (!Inbound)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        std::array<std::uint8_t, 6> Prefix{};
        const auto PrefixRead = co_await Inbound->ReadExact(
            std::as_writable_bytes(std::span<std::uint8_t>(Prefix)));
        if (PrefixRead.Failure.Failed())
        {
            auto Failure = PrefixRead.Failure;
            if (Failure.Code == Prism::Fault::Code::Eof && PrefixRead.Bytes > 0U)
                Failure.Code = Prism::Fault::Code::BadMessage;
            co_return std::unexpected(std::move(Failure));
        }
        if (PrefixRead.Bytes != Prefix.size())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        const auto Length = static_cast<std::size_t>(Prefix[0] << 8U | Prefix[1]);
        Frame Result;
        Result.SessionId = static_cast<std::uint16_t>(Prefix[2] << 8U | Prefix[3]);
        Result.StatusValue = static_cast<Status>(Prefix[4]);
        const auto Option = Prefix[5];
        if (Result.StatusValue == Status::End)
        {
            co_return Result;
        }
        if (Result.StatusValue != Status::New && Result.StatusValue != Status::Keep &&
            Result.StatusValue != Status::KeepAlive)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        if (Length < 4U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        if (Length > 4U)
        {
            std::vector<std::uint8_t> Body(Length - 4U);
            const auto BodyRead = co_await Inbound->ReadExact(
                std::as_writable_bytes(std::span<std::uint8_t>(Body)));
            if (BodyRead.Failure.Failed())
            {
                auto Failure = BodyRead.Failure;
                if (Failure.Code == Prism::Fault::Code::Eof && BodyRead.Bytes > 0U)
                    Failure.Code = Prism::Fault::Code::BadMessage;
                co_return std::unexpected(std::move(Failure));
            }
            if (BodyRead.Bytes != Body.size() || Body.empty())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            if (Body[0] != NetworkUdp)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            auto Target = ReadAddress(std::span<const std::uint8_t>(Body).subspan(1));
            if (!Target)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            Result.Target = std::move(Target->Target);
            Result.HasTarget = true;
        }
        if ((Option & OptionError) != 0U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
        }
        if ((Option & OptionData) == 0U)
        {
            co_return Result;
        }
        std::array<std::uint8_t, 2> PayloadLengthWire{};
        const auto LengthRead = co_await Inbound->ReadExact(
            std::as_writable_bytes(std::span<std::uint8_t>(PayloadLengthWire)));
        if (LengthRead.Failure.Failed())
        {
            auto Failure = LengthRead.Failure;
            if (Failure.Code == Prism::Fault::Code::Eof && LengthRead.Bytes > 0U)
                Failure.Code = Prism::Fault::Code::BadMessage;
            co_return std::unexpected(std::move(Failure));
        }
        if (LengthRead.Bytes != PayloadLengthWire.size())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        const auto PayloadLength = static_cast<std::size_t>(
            PayloadLengthWire[0] << 8U | PayloadLengthWire[1]);
        Result.Payload.resize(PayloadLength);
        const auto PayloadRead = co_await Inbound->ReadExact(
            std::as_writable_bytes(std::span<std::uint8_t>(Result.Payload)));
        if (PayloadRead.Failure.Failed())
        {
            auto Failure = PayloadRead.Failure;
            if (Failure.Code == Prism::Fault::Code::Eof && PayloadRead.Bytes > 0U)
                Failure.Code = Prism::Fault::Code::BadMessage;
            co_return std::unexpected(std::move(Failure));
        }
        if (PayloadRead.Bytes != Result.Payload.size())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        co_return Result;
    }

    /**
     * @brief 写回一个 XUDP 数据帧（长格式：network + port-first 源地址）
     * @param Inbound MUX 根传输
     * @param SessionId 会话号
     * @param Source 上游响应源端点
     * @param Payload 载荷
     * @return 写成功返回 true
     */
    /** @brief 一条完整回包的 owning wire 请求，编码不执行 I/O。 */
    struct Reply final
    {
        std::uint16_t SessionId;
        Net::ip::udp::endpoint Source;
        std::vector<std::uint8_t> Payload;
    };
    [[nodiscard]] inline auto EncodeReply(Reply Value) -> std::vector<std::byte>
    {
        if (Value.Payload.size() > MaxDatagram) return {};
        const auto V4 = Value.Source.address().is_v4();
        const auto Length = static_cast<std::uint16_t>(V4 ? 12 : 24);
        std::vector<std::byte> Wire{std::byte{static_cast<std::uint8_t>(Length >> 8)},
            std::byte{static_cast<std::uint8_t>(Length)},
            std::byte{static_cast<std::uint8_t>(Value.SessionId >> 8)},
            std::byte{static_cast<std::uint8_t>(Value.SessionId)},std::byte{2},std::byte{1},std::byte{2},
            std::byte{static_cast<std::uint8_t>(Value.Source.port() >> 8)},
            std::byte{static_cast<std::uint8_t>(Value.Source.port())},std::byte{static_cast<std::uint8_t>(V4 ? 1 : 3)}};
        const auto Add = [&Wire](auto Address)
        { for (const auto Byte : Address.to_bytes()) Wire.push_back(std::byte{Byte}); };
        if (V4) Add(Value.Source.address().to_v4()); else Add(Value.Source.address().to_v6());
        Wire.push_back(std::byte{static_cast<std::uint8_t>(Value.Payload.size() >> 8)});
        Wire.push_back(std::byte{static_cast<std::uint8_t>(Value.Payload.size())});
        for (const auto Byte : Value.Payload) Wire.push_back(std::byte{Byte});
        return Wire;
    }
    [[nodiscard]] inline auto EncodeEnd(std::uint16_t Id) -> std::vector<std::byte>
    {
        return {std::byte{0},std::byte{4},std::byte{static_cast<std::uint8_t>(Id >> 8)},
            std::byte{static_cast<std::uint8_t>(Id)},std::byte{3},std::byte{OptionError}};
    }
}
