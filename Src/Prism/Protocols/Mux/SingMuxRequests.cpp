/** @file SingMuxRequests.cpp @brief sing-mux 请求读取与 terminal 保存实现。 */
#include "Detail/SingMux/SingMux.hpp"

#include <Prism/Foundation/ByteSpan.hpp>

#include <boost/asio/ip/address_v6.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <array>
#include <new>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Mux::Detail::SingMux
{

    auto SessionDetail::ReadExactField(
        const Prism::SharedTransmission &Raw,
        std::span<std::uint8_t> Buffer)
        -> Net::awaitable<std::expected<ExactFieldReadResult, Prism::Fault::Failure>>
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
        if (Result.Bytes != Buffer.size())
        {
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
        }
        if (Result.Failure.Failed())
        {
            co_return ExactFieldReadResult{Result.Failure};
        }
        co_return ExactFieldReadResult{};
    }

    auto MakeSessionRequest(
        const std::array<std::uint8_t, 2> &Prefix,
        const bool Padding,
        std::optional<Prism::Fault::Failure> Terminal)
        -> std::expected<SessionRequestReadResult, Prism::Fault::Failure>
    {
        auto Wire = Prism::Mux::Mode::Smux;
        switch (Prefix[1])
        {
        case 0U: Wire = Prism::Mux::Mode::Smux; break;
        case 1U: Wire = Prism::Mux::Mode::Yamux; break;
        case 2U: Wire = Prism::Mux::Mode::H2Mux; break;
        default:
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        return SessionRequestReadResult{
            Prism::Mux::SingMux::SessionRequest{Prefix[0], Wire, Padding},
            std::move(Terminal)};
    }

    auto ReadSessionRequest(Prism::SharedTransmission Raw)
        -> Net::awaitable<std::expected<SessionRequestReadResult, Prism::Fault::Failure>>
    {
        if (!Raw)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        std::array<std::uint8_t, 2> Prefix{};
        const auto PrefixRead = co_await SessionDetail::ReadExactField(Raw, Prefix);
        if (!PrefixRead)
        {
            co_return std::unexpected(PrefixRead.error());
        }
        if (Prefix[0] > 1U || Prefix[1] > 2U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }

        if (Prefix[0] == 0U)
        {
            co_return MakeSessionRequest(Prefix, false, PrefixRead->Terminal);
        }
        if (PrefixRead->Terminal)
        {
            co_return std::unexpected(*PrefixRead->Terminal);
        }
        std::array<std::uint8_t, 1> PaddingFlag{};
        const auto FlagRead = co_await SessionDetail::ReadExactField(Raw, PaddingFlag);
        if (!FlagRead) co_return std::unexpected(FlagRead.error());
        if (PaddingFlag[0] > 1U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        const bool Padding = PaddingFlag[0] != 0U;
        if (!Padding)
        {
            co_return MakeSessionRequest(Prefix, false, FlagRead->Terminal);
        }
        if (FlagRead->Terminal)
        {
            co_return std::unexpected(*FlagRead->Terminal);
        }

        std::array<std::uint8_t, 2> PaddingLengthWire{};
        const auto LengthRead = co_await SessionDetail::ReadExactField(Raw, PaddingLengthWire);
        if (!LengthRead) co_return std::unexpected(LengthRead.error());
        const auto PaddingLength =
            static_cast<std::size_t>(PaddingLengthWire[0] << 8U | PaddingLengthWire[1]);
        if (LengthRead->Terminal && PaddingLength != 0U)
        {
            co_return std::unexpected(*LengthRead->Terminal);
        }
        if (PaddingLength == 0U)
        {
            co_return MakeSessionRequest(Prefix, true, LengthRead->Terminal);
        }
        if (LengthRead->Terminal)
        {
            co_return std::unexpected(*LengthRead->Terminal);
        }
        std::vector<std::uint8_t> PaddingBytes;
        try { PaddingBytes.resize(PaddingLength); }
        catch (const std::bad_alloc &)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        const auto PaddingRead = co_await SessionDetail::ReadExactField(Raw, PaddingBytes);
        if (!PaddingRead) co_return std::unexpected(PaddingRead.error());
        co_return MakeSessionRequest(Prefix, true, PaddingRead->Terminal);
    }

    auto ReadStreamRequest(Prism::SharedTransmission Raw)
        -> Net::awaitable<std::expected<StreamRequestReadResult, Prism::Fault::Failure>>
    {
        if (!Raw)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        std::array<std::uint8_t, 3> Prefix{};
        const auto PrefixRead = co_await SessionDetail::ReadExactField(Raw, Prefix);
        if (!PrefixRead) co_return std::unexpected(PrefixRead.error());
        const auto Flags = static_cast<std::uint16_t>(Prefix[0] << 8U | Prefix[1]);
        const auto AddressFamily = Prefix[2];
        Prism::Network::Target Target;
        switch (AddressFamily)
        {
        case 0x00:
            Target.Route = Prism::Network::RouteKind::Forward;
            co_return StreamRequestReadResult{
                StreamRequest{.Target = std::move(Target), .Flags = Flags,
                    .Udp = (Flags & 0x0001U) != 0U,
                    .PacketAddress = (Flags & 0x0002U) != 0U},
                PrefixRead->Terminal};
        case 0x01: {
            std::array<std::uint8_t, 4> Address{};
            if (PrefixRead->Terminal) co_return std::unexpected(*PrefixRead->Terminal);
            const auto AddressRead = co_await SessionDetail::ReadExactField(Raw, Address);
            if (!AddressRead) co_return std::unexpected(AddressRead.error());
            Target.Host = Prism::Network::Host(Prism::Network::Ipv4Bytes{Address});
            if (AddressRead->Terminal) co_return std::unexpected(*AddressRead->Terminal);
            break;
        }
        case 0x03: {
            std::array<std::uint8_t, 1> Length{};
            if (PrefixRead->Terminal)
            {
                co_return std::unexpected(*PrefixRead->Terminal);
            }
            const auto LengthRead = co_await SessionDetail::ReadExactField(Raw, Length);
            if (!LengthRead) co_return std::unexpected(LengthRead.error());
            if (Length[0] == 0U)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            }
            if (LengthRead->Terminal) co_return std::unexpected(*LengthRead->Terminal);
            std::vector<std::uint8_t> Host(Length[0]);
            const auto HostRead = co_await SessionDetail::ReadExactField(Raw, Host);
            if (!HostRead) co_return std::unexpected(HostRead.error());
            auto Domain = Prism::Network::DecodeHost(Prism::Network::HostEncoding::Domain,
                {reinterpret_cast<const char *>(Host.data()), Host.size()});
            if (!Domain)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            }
            Target.Host = std::move(*Domain);
            if (HostRead->Terminal) co_return std::unexpected(*HostRead->Terminal);
            break;
        }
        case 0x04: {
            std::array<std::uint8_t, 16> Address{};
            if (PrefixRead->Terminal) co_return std::unexpected(*PrefixRead->Terminal);
            const auto AddressRead = co_await SessionDetail::ReadExactField(Raw, Address);
            if (!AddressRead) co_return std::unexpected(AddressRead.error());
            boost::asio::ip::address_v6::bytes_type Bytes{};
            std::copy(Address.begin(), Address.end(), Bytes.begin());
            Target.Host = Prism::Network::Host(Prism::Network::Ipv6Bytes{Bytes});
            if (AddressRead->Terminal) co_return std::unexpected(*AddressRead->Terminal);
            break;
        }
        default:
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        std::array<std::uint8_t, 2> Port{};
        const auto PortRead = co_await SessionDetail::ReadExactField(Raw, Port);
        if (!PortRead) co_return std::unexpected(PortRead.error());
        Target.Port = static_cast<std::uint16_t>(Port[0] << 8U | Port[1]);
        Target.Route = Prism::Network::RouteKind::Forward;
        co_return StreamRequestReadResult{
            StreamRequest{.Target = std::move(Target), .Flags = Flags,
                .Udp = (Flags & 0x0001U) != 0U,
                .PacketAddress = (Flags & 0x0002U) != 0U},
            PortRead->Terminal};
    }

} // namespace Prism::Mux::Detail::SingMux
