/**
 * @file SingMux.hpp
 * @brief sing-mux 会话协商、虚拟流请求与服务端响应适配。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Mux/Detail/SingMux/Codec.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Mux::Detail::SingMux
{

    namespace Net = boost::asio;

    enum class Protocol : std::uint8_t
    {
        Smux = 0,
        Yamux = 1,
        H2Mux = 2,
    };

    struct SessionRequest final
    {
        std::uint8_t Version{0};
        Protocol ProtocolValue{Protocol::Smux};
        bool Padding{false};
    };

    namespace SessionDetail
    {
        /** @brief 精确读取协商字段并保留每次 partial I/O 的首个 typed/native cause。 */
        [[nodiscard]] inline auto ReadExact(
            const Prism::SharedTransmission &Raw,
            std::span<std::uint8_t> Buffer)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Raw)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            Prism::IoResult Result;
            try { Result = co_await Raw->ReadExact(Prism::AsBytes(Buffer)); }
            catch (const boost::system::system_error &Error)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            {
                co_return std::unexpected(Prism::Fault::FromNative(Error.code()));
            }
            catch (const std::bad_alloc &)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            }
            catch (...)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            if (Result.Bytes > Buffer.size())
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument, Result.Failure.Native});
            }
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            if (Result.Bytes != Buffer.size())
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
    }

    [[nodiscard]] inline auto ReadSessionRequest(Prism::SharedTransmission Raw)
        -> Net::awaitable<std::expected<SessionRequest, Prism::Fault::Failure>>
    {
        if (!Raw)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        std::array<std::uint8_t, 2> Prefix{};
        const auto PrefixRead = co_await SessionDetail::ReadExact(Raw, Prefix);
        if (!PrefixRead)
        {
            co_return std::unexpected(PrefixRead.error());
        }
        if (Prefix[0] > 1U || Prefix[1] > 2U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }

        bool Padding = false;
        if (Prefix[0] == 1U)
        {
            std::array<std::uint8_t, 1> PaddingFlag{};
            const auto FlagRead = co_await SessionDetail::ReadExact(Raw, PaddingFlag);
            if (!FlagRead) co_return std::unexpected(FlagRead.error());
            if (PaddingFlag[0] > 1U)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            Padding = PaddingFlag[0] != 0U;
            if (Padding)
            {
                std::array<std::uint8_t, 2> PaddingLengthWire{};
                const auto LengthRead = co_await SessionDetail::ReadExact(Raw, PaddingLengthWire);
                if (!LengthRead)
                {
                    co_return std::unexpected(LengthRead.error());
                }
                const auto PaddingLength =
                    static_cast<std::size_t>(PaddingLengthWire[0] << 8U | PaddingLengthWire[1]);
                std::vector<std::uint8_t> PaddingBytes;
                try { PaddingBytes.resize(PaddingLength); }
                catch (const std::bad_alloc &)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
                }
                const auto PaddingRead = co_await SessionDetail::ReadExact(Raw, PaddingBytes);
                if (!PaddingRead) co_return std::unexpected(PaddingRead.error());
            }
        }
        co_return SessionRequest{Prefix[0], static_cast<Protocol>(Prefix[1]), Padding};
    }

    [[nodiscard]] inline auto ReadStreamRequest(Prism::SharedTransmission Raw)
        -> Net::awaitable<std::optional<StreamRequest>>
    {
        if (!Raw)
        {
            co_return std::nullopt;
        }
        std::array<std::uint8_t, 3> Prefix{};
        if (!(co_await SessionDetail::ReadExact(Raw, Prefix)))
        {
            co_return std::nullopt;
        }
        const auto Flags = static_cast<std::uint16_t>(Prefix[0] << 8U | Prefix[1]);
        const auto AddressFamily = Prefix[2];
        Prism::Network::Target Target;
        switch (AddressFamily)
        {
        case 0x00:
            break;
        case 0x01: {
            std::array<std::uint8_t, 4> Address{};
            if (!(co_await SessionDetail::ReadExact(Raw, Address)))
            {
                co_return std::nullopt;
            }
            Target.Host = Prism::Network::Host(Prism::Network::Ipv4Bytes{Address});
            break;
        }
        case 0x03: {
            std::array<std::uint8_t, 1> Length{};
            if (!(co_await SessionDetail::ReadExact(Raw, Length)) || Length[0] == 0U)
            {
                co_return std::nullopt;
            }
            std::vector<std::uint8_t> Host(Length[0]);
            if (!(co_await SessionDetail::ReadExact(Raw, Host)))
            {
                co_return std::nullopt;
            }
            auto Domain = Prism::Network::DecodeHost(Prism::Network::HostEncoding::Domain,
                {reinterpret_cast<const char *>(Host.data()), Host.size()});
            if (!Domain) co_return std::nullopt;
            Target.Host = std::move(*Domain);
            break;
        }
        case 0x04: {
            std::array<std::uint8_t, 16> Address{};
            if (!(co_await SessionDetail::ReadExact(Raw, Address)))
            {
                co_return std::nullopt;
            }
            boost::asio::ip::address_v6::bytes_type Bytes{};
            std::copy(Address.begin(), Address.end(), Bytes.begin());
            Target.Host = Prism::Network::Host(Prism::Network::Ipv6Bytes{Bytes});
            break;
        }
        default:
            co_return std::nullopt;
        }
        if (AddressFamily != 0x00)
        {
            std::array<std::uint8_t, 2> Port{};
            if (!(co_await SessionDetail::ReadExact(Raw, Port)))
            {
                co_return std::nullopt;
            }
            Target.Port = static_cast<std::uint16_t>(Port[0] << 8U | Port[1]);
        }
        Target.Route = Prism::Network::RouteKind::Forward;
        co_return StreamRequest{.Target = std::move(Target), .Flags = Flags,
            .Udp = (Flags & 0x0001U) != 0U, .PacketAddress = (Flags & 0x0002U) != 0U};
    }

}
