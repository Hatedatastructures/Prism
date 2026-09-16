/**
 * @file UdpService.hpp
 * @brief Preview-owned protocol UDP service factories.
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Protocols/Socks5/Conn.hpp>
#include <Preview/Protocols/Socks5/UdpAssoc.hpp>
#include <Preview/Protocols/Trojan/Dgram.hpp>
#include <Preview/Protocols/Trojan/Types.hpp>
#include <Preview/Protocols/Vless/Conn.hpp>
#include <Preview/Protocols/Vless/UdpTunnel.hpp>
#include <Preview/Protocols/Vmess/Dgram.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/SessionServices.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Composition
{

    namespace Net = boost::asio;

    struct UdpResolveRequest final
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    struct UdpServiceOptions final
    {
        using ResolverFn = std::function<Net::awaitable<std::pair<Preview::Error,
                                                                    Net::ip::udp::endpoint>>(
            UdpResolveRequest)>;

        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)};
        ResolverFn Resolver{};
    };

    class UdpServiceFactory final
    {
    public:
        using ServiceFn = Preview::Runtime::SessionServices::UdpServiceFn;
        using Udp = Net::ip::udp;

        [[nodiscard]] static auto MakeSocks5(UdpServiceOptions Options = {}) -> ServiceFn
        {
            return [Options = std::move(Options)](Preview::Middleware::Context &Context)
                -> Net::awaitable<Preview::Fault::Code>
            {
                auto Carrier = std::dynamic_pointer_cast<Preview::Socks5::Conn<>>(
                    Context.Inbound);
                if (!Carrier)
                {
                    Close(Context.Inbound);
                    co_return Preview::Fault::Code::ProtocolError;
                }
                Preview::Socks5::UdpAssocOptions AssocOptions;
                AssocOptions.IdleTimeout = Options.IdleTimeout;
                AssocOptions.traffic = Context.traffic;
                AssocOptions.identity = Context.identity;
                AssocOptions.resolve = [Resolver = Options.Resolver](
                                            const Preview::Socks5::Address &Address)
                    -> Net::awaitable<std::pair<Preview::Error, Net::ip::udp::endpoint>>
                {
                    if (Resolver)
                    {
                        co_return co_await Resolver(
                            UdpResolveRequest{Address.Host, Address.Port});
                    }
                    co_return ResolveIp(Address.Host, Address.Port);
                };
                auto Service = std::make_shared<Preview::Socks5::UdpAssoc>(
                    Context.Inbound->Executor(), std::move(Carrier), std::move(AssocOptions));
                const auto BindError = co_await Service->BindAndReply();
                if (BindError != Preview::Error::None)
                {
                    Close(Context.Inbound);
                    co_return Preview::Fault::ToCode(
                        Preview::make_error_code(BindError));
                }
                co_await Service->Run();
                Close(Context.Inbound);
                co_return Preview::Fault::Code::Success;
            };
        }

        [[nodiscard]] static auto MakeVless(UdpServiceOptions Options = {}) -> ServiceFn
        {
            return [Options = std::move(Options)](Preview::Middleware::Context &Context)
                -> Net::awaitable<Preview::Fault::Code>
            {
                auto Carrier = std::dynamic_pointer_cast<Preview::Vless::Conn<>>(
                    Context.Inbound);
                if (!Carrier)
                {
                    Close(Context.Inbound);
                    co_return Preview::Fault::Code::ProtocolError;
                }
                Preview::Vless::UdpTunnelOptions TunnelOptions;
                TunnelOptions.IdleTimeout = Options.IdleTimeout;
                TunnelOptions.traffic = Context.traffic;
                TunnelOptions.identity = Context.identity;
                TunnelOptions.resolve = [Resolver = Options.Resolver](
                                             const Preview::Vless::Address &Address)
                    -> Net::awaitable<std::pair<Preview::Error, Net::ip::udp::endpoint>>
                {
                    if (Resolver)
                    {
                        co_return co_await Resolver(
                            UdpResolveRequest{Address.Host, Address.Port});
                    }
                    co_return ResolveIp(Address.Host, Address.Port);
                };
                auto Service = std::make_shared<Preview::Vless::UdpTunnel>(
                    std::move(Carrier), std::move(TunnelOptions));
                co_await Service->Run();
                Close(Context.Inbound);
                co_return Preview::Fault::Code::Success;
            };
        }

        [[nodiscard]] static auto MakeTrojan(UdpServiceOptions Options = {}) -> ServiceFn
        {
            return [Options = std::move(Options)](Preview::Middleware::Context &Context)
                -> Net::awaitable<Preview::Fault::Code>
            {
                auto Carrier = std::dynamic_pointer_cast<Preview::Trojan::Dgram<>>(
                    Context.Inbound);
                if (!Carrier)
                {
                    Close(Context.Inbound);
                    co_return Preview::Fault::Code::ProtocolError;
                }
                co_return co_await RunStreamDatagrams(
                    TrojanPacketAdapter{std::move(Carrier)}, Options,
                    Context.traffic, Context.identity);
            };
        }

        [[nodiscard]] static auto MakeVmess(UdpServiceOptions Options = {}) -> ServiceFn
        {
            return [Options = std::move(Options)](Preview::Middleware::Context &Context)
                -> Net::awaitable<Preview::Fault::Code>
            {
                auto Carrier = std::dynamic_pointer_cast<Preview::Vmess::Dgram<>>(
                    Context.Inbound);
                if (!Carrier)
                {
                    Close(Context.Inbound);
                    co_return Preview::Fault::Code::ProtocolError;
                }
                unsigned int Port = 0;
                const auto *Begin = Context.Target.Port.data();
                const auto *End = Begin + Context.Target.Port.size();
                const auto Parsed = std::from_chars(Begin, End, Port);
                if (Context.Target.Host.empty() || Parsed.ec != std::errc{} ||
                    Parsed.ptr != End || Port == 0U || Port > 65535U)
                {
                    Close(Context.Inbound);
                    co_return Preview::Fault::Code::InvalidArgument;
                }
                UdpResolveRequest Target{
                    std::string(Context.Target.Host), static_cast<std::uint16_t>(Port)};
                co_return co_await RunStreamDatagrams(
                    VmessPacketAdapter{std::move(Carrier), std::move(Target)}, Options,
                    Context.traffic, Context.identity);
            };
        }

        [[nodiscard]] static auto MakeSs2022() -> ServiceFn
        {
            return [](Preview::Middleware::Context &Context)
                -> Net::awaitable<Preview::Fault::Code>
            {
                Close(Context.Inbound);
                co_return Preview::Fault::Code::NotSupported;
            };
        }

    private:
        struct StreamDatagramPacket final
        {
            UdpResolveRequest Target;
            std::vector<std::uint8_t> Payload;
        };

        struct TrojanPacketAdapter final
        {
            std::shared_ptr<Preview::Trojan::Dgram<>> Carrier;

            [[nodiscard]] auto Executor() const -> Net::any_io_executor
            {
                return Carrier->Executor();
            }

            [[nodiscard]] auto Receive(StreamDatagramPacket &Packet)
                -> Net::awaitable<Preview::Error>
            {
                Preview::Trojan::Address Target;
                const auto Result = co_await Carrier->AsyncReceiveFrom(Target, Packet.Payload);
                if (Result == Preview::Error::None)
                {
                    Packet.Target = UdpResolveRequest{std::move(Target.Host), Target.Port};
                }
                co_return Result;
            }

            [[nodiscard]] auto Send(const Udp::endpoint &Source,
                                    std::span<const std::uint8_t> Payload)
                -> Net::awaitable<Preview::Error>
            {
                const auto Type = Source.address().is_v4()
                                      ? Preview::Trojan::AddressType::Ipv4
                                      : Preview::Trojan::AddressType::Ipv6;
                Preview::Trojan::Address Address{
                    Type, Source.address().to_string(), Source.port()};
                co_return co_await Carrier->AsyncSendTo(Address, Payload);
            }

            auto Cancel() const -> void { Carrier->Cancel(); }
            auto Close() const -> void { Carrier->Close(); }
        };

        struct VmessPacketAdapter final
        {
            std::shared_ptr<Preview::Vmess::Dgram<>> Carrier;
            UdpResolveRequest FixedTarget;

            [[nodiscard]] auto Executor() const -> Net::any_io_executor
            {
                return Carrier->Executor();
            }

            [[nodiscard]] auto Receive(StreamDatagramPacket &Packet)
                -> Net::awaitable<Preview::Error>
            {
                const auto Result = co_await Carrier->AsyncReceiveFrom(Packet.Payload);
                if (Result == Preview::Error::None)
                {
                    Packet.Target = FixedTarget;
                }
                co_return Result;
            }

            [[nodiscard]] auto Send(const Udp::endpoint &,
                                    std::span<const std::uint8_t> Payload)
                -> Net::awaitable<Preview::Error>
            {
                co_return co_await Carrier->AsyncSendTo(Payload);
            }

            auto Cancel() const -> void { Carrier->Cancel(); }
            auto Close() const -> void { Carrier->Close(); }
        };

        template <typename Adapter>
        [[nodiscard]] static auto RunStreamDatagrams(
            Adapter AdapterValue,
            UdpServiceOptions Options,
            Preview::Foundation::TrafficSink *Traffic,
            std::string Identity) -> Net::awaitable<Preview::Fault::Code>
        {
            Udp::socket Egress(AdapterValue.Executor());
            std::vector<std::byte> UpstreamBuffer(65535);
            std::size_t SentBytes = 0;
            std::size_t ReceivedBytes = 0;
            auto Result = Preview::Fault::Code::Success;

            while (true)
            {
                StreamDatagramPacket Packet;
                const auto PacketError = co_await WaitForPacket(
                    AdapterValue, Packet, Options.IdleTimeout);
                if (!PacketError)
                {
                    break;
                }
                if (*PacketError != Preview::Error::None)
                {
                    Result = Preview::Fault::ToCode(
                        Preview::make_error_code(*PacketError));
                    break;
                }

                const auto [ResolveError, Target] = co_await ResolveTarget(
                    Options, Packet.Target);
                if (ResolveError != Preview::Error::None)
                {
                    continue;
                }

                auto ErrorCode = OpenSocket(Egress, Target.protocol());
                if (ErrorCode)
                {
                    Result = Preview::Fault::ToCode(ErrorCode);
                    break;
                }
                co_await Egress.async_send_to(
                    Net::buffer(Packet.Payload), Target,
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode)
                {
                    Result = Preview::Fault::ToCode(ErrorCode);
                    break;
                }
                SentBytes += Packet.Payload.size();

                Udp::endpoint Source;
                const auto Received = co_await ReceiveUpstream(
                    Egress, UpstreamBuffer, Source, ErrorCode, Options.IdleTimeout);
                if (!Received)
                {
                    break;
                }
                if (ErrorCode)
                {
                    Result = Preview::Fault::ToCode(ErrorCode);
                    break;
                }
                const auto Payload = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(UpstreamBuffer.data()), *Received);
                const auto SendError = co_await AdapterValue.Send(Source, Payload);
                if (SendError != Preview::Error::None)
                {
                    Result = Preview::Fault::ToCode(
                        Preview::make_error_code(SendError));
                    break;
                }
                ReceivedBytes += *Received;
            }

            boost::system::error_code ErrorCode;
            Egress.cancel(ErrorCode);
            Egress.close(ErrorCode);
            AdapterValue.Cancel();
            AdapterValue.Close();
            if (Traffic != nullptr)
            {
                Traffic->Report(Identity, SentBytes, ReceivedBytes);
            }
            co_return Result;
        }

        template <typename Adapter>
        [[nodiscard]] static auto WaitForPacket(
            Adapter &AdapterValue,
            StreamDatagramPacket &Packet,
            std::chrono::milliseconds IdleTimeout)
            -> Net::awaitable<std::optional<Preview::Error>>
        {
            auto Receive = AdapterValue.Receive(Packet);
            if (IdleTimeout.count() <= 0)
            {
                co_return co_await std::move(Receive);
            }
            Net::steady_timer Timer(AdapterValue.Executor());
            Timer.expires_after(IdleTimeout);
            using boost::asio::experimental::awaitable_operators::operator||;
            auto Race = co_await (
                std::move(Receive) || Timer.async_wait(Net::use_awaitable));
            if (Race.index() == 1)
            {
                co_return std::nullopt;
            }
            co_return std::get<0>(std::move(Race));
        }

        [[nodiscard]] static auto ReceiveUpstream(
            Udp::socket &Socket,
            std::span<std::byte> Buffer,
            Udp::endpoint &Source,
            boost::system::error_code &ErrorCode,
            std::chrono::milliseconds IdleTimeout)
            -> Net::awaitable<std::optional<std::size_t>>
        {
            auto Receive = Socket.async_receive_from(
                Net::buffer(Buffer), Source,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (IdleTimeout.count() <= 0)
            {
                co_return co_await std::move(Receive);
            }
            Net::steady_timer Timer(Socket.get_executor());
            Timer.expires_after(IdleTimeout);
            using boost::asio::experimental::awaitable_operators::operator||;
            auto Race = co_await (
                std::move(Receive) || Timer.async_wait(Net::use_awaitable));
            if (Race.index() == 1)
            {
                co_return std::nullopt;
            }
            co_return std::get<0>(std::move(Race));
        }

        [[nodiscard]] static auto ResolveTarget(
            const UdpServiceOptions &Options,
            UdpResolveRequest Request)
            -> Net::awaitable<std::pair<Preview::Error, Udp::endpoint>>
        {
            if (Options.Resolver)
            {
                co_return co_await Options.Resolver(std::move(Request));
            }
            boost::system::error_code ErrorCode;
            const auto Address = Net::ip::make_address(Request.Host, ErrorCode);
            if (ErrorCode)
            {
                co_return std::pair{Preview::Error::BadAddress, Udp::endpoint{}};
            }
            co_return std::pair{
                Preview::Error::None, Udp::endpoint(Address, Request.Port)};
        }

        [[nodiscard]] static auto OpenSocket(
            Udp::socket &Socket,
            Udp Protocol) -> boost::system::error_code
        {
            boost::system::error_code ErrorCode;
            if (Socket.is_open())
            {
                const auto Local = Socket.local_endpoint(ErrorCode);
                if (!ErrorCode && Local.protocol() == Protocol)
                {
                    return {};
                }
                Socket.close(ErrorCode);
                if (ErrorCode)
                {
                    return ErrorCode;
                }
            }
            Socket.open(Protocol, ErrorCode);
            return ErrorCode;
        }

        static auto Close(const Preview::SharedTransmission &Transport) noexcept -> void
        {
            if (Transport)
            {
                Transport->Cancel();
                Transport->Close();
            }
        }

        static auto ResolveIp(const std::string &Host, const std::uint16_t Port)
            -> std::pair<Preview::Error, Net::ip::udp::endpoint>
        {
            boost::system::error_code ErrorCode;
            const auto Address = Net::ip::make_address(Host, ErrorCode);
            if (ErrorCode)
            {
                return {Preview::Error::BadAddress, {}};
            }
            return {Preview::Error::None, Net::ip::udp::endpoint(Address, Port)};
        }
    };

} // namespace Preview::Composition
