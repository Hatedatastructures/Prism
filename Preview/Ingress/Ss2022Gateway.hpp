/**
 * @file Ss2022Gateway.hpp
 * @brief SS2022 独立 UDP ingress、认证和 outbound relay。
 */
#pragma once

#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Ingress/UdpDemux.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Protocols/Shadowsocks2022/ResponseCodec.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <openssl/rand.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Ingress
{

    namespace Net = boost::asio;
    namespace Ss = Preview::Shadowsocks2022;

    class Ss2022Gateway final : public std::enable_shared_from_this<Ss2022Gateway>
    {
    public:
        using Endpoint = Net::ip::udp::endpoint;
        using SendFn = std::function<Net::awaitable<boost::system::error_code>(
            std::span<const std::byte>, const Endpoint &)>;

        struct Options final
        {
            Net::any_io_executor Executor;
            std::vector<std::array<std::uint8_t, 16>> Keys;
            std::shared_ptr<Preview::Network::Dns::Resolver> Resolver;
            SendFn Send;
            std::uint64_t TimeWindow{90};
            std::chrono::milliseconds RelayTimeout{2000};
            std::chrono::milliseconds PeerIdleTimeout{60000};
            std::size_t MaxPeers{1024};
        };

        explicit Ss2022Gateway(Options OptionsValue)
            : Options_(std::move(OptionsValue)), Strand_(Net::make_strand(Options_.Executor))
        {
        }

        [[nodiscard]] auto Handle(UdpPacket Packet) -> bool
        {
            const auto IsOrdinary = Packet.Classification.Kind == DatagramKind::Ordinary;
            const auto IsUnclaimedQuic =
                Packet.Classification.Kind == DatagramKind::Quic &&
                Packet.Classification.Route == DatagramRoute::UnknownCid;
            if (Closed_.load(std::memory_order_acquire) ||
                (!IsOrdinary && !IsUnclaimedQuic) || !Options_.Send || Options_.Keys.empty())
            {
                return false;
            }
            const auto Self = shared_from_this();
            Net::co_spawn(
                Strand_,
                [Self, Packet = std::move(Packet)]() mutable -> Net::awaitable<void>
                {
                    co_await Self->Process(std::move(Packet));
                },
                Net::detached);
            return true;
        }

        auto Close() noexcept -> void
        {
            Closed_.store(true, std::memory_order_release);
            const auto Self = shared_from_this();
            Net::post(Strand_, [Self] { Self->Peers_.clear(); });
        }

    private:
        struct PeerState final
        {
            std::array<std::uint8_t, 16> Key{};
            std::array<std::uint8_t, Ss::SessionIdLen> ClientSession{};
            std::array<std::uint8_t, Ss::SessionIdLen> ServerSession{};
            std::uint64_t HighestPacket{0};
            std::uint64_t ReplayBits{0};
            std::uint64_t NextPacket{0};
            std::chrono::steady_clock::time_point LastSeen{};
        };

        [[nodiscard]] static auto PeerKey(const Endpoint &Peer) -> std::string
        {
            return Peer.address().to_string() + ":" + std::to_string(Peer.port());
        }

        [[nodiscard]] static auto AcceptPacketId(PeerState &State,
                                                  const std::uint64_t PacketId) noexcept -> bool
        {
            if (State.ReplayBits == 0)
            {
                State.HighestPacket = PacketId;
                State.ReplayBits = 1;
                return true;
            }
            if (PacketId > State.HighestPacket)
            {
                const auto Shift = PacketId - State.HighestPacket;
                State.ReplayBits = Shift >= 64U ? 1ULL : (State.ReplayBits << Shift) | 1ULL;
                State.HighestPacket = PacketId;
                return true;
            }
            const auto Distance = State.HighestPacket - PacketId;
            if (Distance >= 64U)
            {
                return false;
            }
            const auto Mask = 1ULL << Distance;
            if ((State.ReplayBits & Mask) != 0U)
            {
                return false;
            }
            State.ReplayBits |= Mask;
            return true;
        }

        [[nodiscard]] auto Resolve(const Ss::Address &Target)
            -> Net::awaitable<std::pair<Preview::Error, Endpoint>>
        {
            if (Options_.Resolver)
            {
                std::error_code ResolveError;
                const auto Addresses = co_await Options_.Resolver->AsyncResolve(
                    Target.Host, ResolveError);
                if (Addresses.empty())
                {
                    co_return std::pair{Preview::Error::BadAddress, Endpoint{}};
                }
                co_return std::pair{Preview::Error::None, Endpoint(Addresses.front(), Target.Port)};
            }
            boost::system::error_code Error;
            const auto Address = Net::ip::make_address(Target.Host, Error);
            if (Error)
            {
                co_return std::pair{Preview::Error::BadAddress, Endpoint{}};
            }
            co_return std::pair{Preview::Error::None, Endpoint(Address, Target.Port)};
        }

        [[nodiscard]] auto Process(UdpPacket Packet) -> Net::awaitable<void>
        {
            if (Closed_.load(std::memory_order_acquire))
            {
                co_return;
            }
            ReapPeers();
            std::vector<std::uint8_t> Bytes;
            Bytes.reserve(Packet.Payload.size());
            for (const auto Byte : Packet.Payload)
            {
                Bytes.push_back(std::to_integer<std::uint8_t>(Byte));
            }

            Ss::Address Target;
            std::vector<std::uint8_t> Payload;
            std::array<std::uint8_t, Ss::SessionIdLen> SessionId{};
            std::uint64_t PacketId = 0;
            std::uint8_t HeaderType = Ss::HeaderTypeClient;
            std::array<std::uint8_t, 16> MatchedKey{};
            bool Authenticated = false;
            for (const auto &Key : Options_.Keys)
            {
                const auto Error = Ss::ParseUdpPacket(Ss::UdpParseInput{
                    std::span<const std::uint8_t>(Key), Bytes, &Target, &Payload, &SessionId,
                    &PacketId, nullptr, &HeaderType, nullptr, 0, Options_.TimeWindow});
                if (Error == Preview::Error::None)
                {
                    MatchedKey = Key;
                    Authenticated = true;
                    break;
                }
            }
            if (!Authenticated || HeaderType != Ss::HeaderTypeClient || !AcceptPeer(Packet.Peer, MatchedKey, SessionId, PacketId))
            {
                co_return;
            }

            const auto [ResolveError, Remote] = co_await Resolve(Target);
            if (ResolveError != Preview::Error::None)
            {
                co_return;
            }
            Net::ip::udp::socket Socket(Strand_);
            boost::system::error_code Error;
            Socket.open(Remote.protocol(), Error);
            if (Error)
            {
                co_return;
            }
            co_await Socket.async_send_to(
                Net::buffer(Payload), Remote,
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return;
            }

            std::array<std::byte, 65535> Buffer{};
            Endpoint Source;
            Net::steady_timer Timer(Strand_);
            Timer.expires_after(Options_.RelayTimeout);
            using Net::experimental::awaitable_operators::operator||;
            auto Race = co_await (
                Socket.async_receive_from(Net::buffer(Buffer), Source,
                                          Net::redirect_error(Net::use_awaitable, Error)) ||
                Timer.async_wait(Net::use_awaitable));
            if (Race.index() == 1 || Error)
            {
                co_return;
            }
            const auto Received = std::get<0>(Race);

            auto It = Peers_.find(PeerKey(Packet.Peer));
            if (It == Peers_.end())
            {
                co_return;
            }
            Ss::Address ResponseTarget{Source.address().is_v4() ? Ss::AddressType::Ipv4
                                                                : Ss::AddressType::Ipv6,
                                       Source.address().to_string(), Source.port()};
            std::vector<std::uint8_t> Wire;
            if (!Ss::BuildUdpPacket(Ss::UdpBuildInput{
                                        std::span<const std::uint8_t>(It->second.Key),
                                        It->second.NextPacket++, &ResponseTarget,
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t *>(Buffer.data()), Received),
                                        It->second.ServerSession, 0, It->second.ClientSession,
                                        Ss::HeaderTypeServer},
                                    Wire))
            {
                co_return;
            }
            if (Options_.Send)
            {
                std::vector<std::byte> Output;
                Output.reserve(Wire.size());
                for (const auto Byte : Wire)
                {
                    Output.push_back(static_cast<std::byte>(Byte));
                }
                (void)co_await Options_.Send(Output, Packet.Peer);
            }
        }

        [[nodiscard]] auto AcceptPeer(const Endpoint &Peer,
                                      const std::array<std::uint8_t, 16> &Key,
                                      const std::array<std::uint8_t, Ss::SessionIdLen> &Session,
                                      const std::uint64_t PacketId) -> bool
        {
            const auto Name = PeerKey(Peer);
            auto It = Peers_.find(Name);
            if (It == Peers_.end())
            {
                if (Peers_.size() >= Options_.MaxPeers)
                {
                    return false;
                }
                PeerState State;
                State.Key = Key;
                State.ClientSession = Session;
                if (RAND_bytes(State.ServerSession.data(), static_cast<int>(State.ServerSession.size())) != 1)
                {
                    return false;
                }
                It = Peers_.emplace(Name, std::move(State)).first;
            }
            else if (It->second.Key != Key)
            {
                return false;
            }
            else if (It->second.ClientSession != Session)
            {
                It->second.ClientSession = Session;
                It->second.HighestPacket = 0;
                It->second.ReplayBits = 0;
                It->second.NextPacket = 0;
            }
            It->second.LastSeen = std::chrono::steady_clock::now();
            return AcceptPacketId(It->second, PacketId);
        }

        auto ReapPeers() -> void
        {
            if (Options_.PeerIdleTimeout.count() <= 0)
            {
                return;
            }
            const auto Now = std::chrono::steady_clock::now();
            for (auto It = Peers_.begin(); It != Peers_.end();)
            {
                if (It->second.LastSeen != std::chrono::steady_clock::time_point{} &&
                    Now - It->second.LastSeen > Options_.PeerIdleTimeout)
                {
                    It = Peers_.erase(It);
                }
                else
                {
                    ++It;
                }
            }
        }

        Options Options_;
        Net::strand<Net::any_io_executor> Strand_;
        std::unordered_map<std::string, PeerState> Peers_;
        std::atomic<bool> Closed_{false};
    };

} // namespace Preview::Ingress
