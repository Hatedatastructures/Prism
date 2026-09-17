/**
 * @file QuicCidRegistry.hpp
 * @brief QUIC CID 到独立 Native Server state 的 owner registry。
 */
#pragma once

#include <Preview/Ingress/UdpDemux.hpp>
#include <Preview/Ingress/QuicAdmissionContext.hpp>
#include <Preview/Protocols/Quic/Native.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/udp.hpp>

#include <cstddef>
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
    using Udp = Net::ip::udp;

    class QuicCidRegistry final
    {
    public:
        using Cid = std::vector<std::byte>;
        using ServerFactory = std::function<std::shared_ptr<Preview::Quic::Server>(
            std::span<const std::byte>, const Udp::endpoint &, SharedQuicAdmissionContext)>;

        struct Options final
        {
            ServerFactory Factory;
            SharedQuicAdmissionContext Context;
        };

        explicit QuicCidRegistry(Options OptionsValue) : Options_(std::move(OptionsValue)) {}

        [[nodiscard]] auto Register(Cid ConnectionId,
                                    std::shared_ptr<Preview::Quic::Server> Server,
                                    Udp::endpoint Peer,
                                    SharedQuicAdmissionContext Context = {}) -> bool
        {
            if (!Context)
            {
                Context = Options_.Context;
            }
            const auto Key = MakeKey(ConnectionId);
            if (Closed_ || Draining_ || Key.empty() || !Server || !Context ||
                !Context->Ready())
            {
                return false;
            }
            if (Entries_.contains(Key))
            {
                return false;
            }
            for (const auto &[ExistingKey, Entry] : Entries_)
            {
                (void)ExistingKey;
                if (Entry.Peer == Peer)
                {
                    return false;
                }
            }
            Entries_.emplace(Key, Entry{std::move(ConnectionId), std::move(Server), Peer,
                                        std::move(Context)});
            return true;
        }

        [[nodiscard]] auto Handle(UdpPacket Packet) -> bool
        {
            if (Closed_ || Draining_)
            {
                return false;
            }
            if (Packet.Classification.ConnectionIdBytes.empty())
            {
                // A short-header packet cannot reveal its CID length before a
                // CID is known. The source endpoint is the remaining stable
                // owner key, so route it to the existing connection rather
                // than dropping a valid newly-issued CID.
                for (const auto &[ExistingKey, Existing] : Entries_)
                {
                    (void)ExistingKey;
                    if (Existing.Peer == Packet.Peer && Existing.Server)
                    {
                        const auto Accepted = Existing.Server->ReceivePacket(
                            Packet.Payload, Packet.Peer);
                        return Accepted;
                    }
                }
                return false;
            }
            const auto Key = MakeKey(Packet.Classification.ConnectionIdBytes);
            if (const auto It = Entries_.find(Key); It != Entries_.end())
            {
                if (It->second.Peer != Packet.Peer)
                {
                    return false;
                }
                return It->second.Server->ReceivePacket(Packet.Payload, Packet.Peer);
            }
            // QUIC servers may advertise new destination CIDs during a live
            // connection. Keep those aliases attached to the existing server
            // owner; explicit Register still rejects peer conflicts so callers
            // cannot accidentally merge independent connections.
            for (const auto &[ExistingKey, Existing] : Entries_)
            {
                (void)ExistingKey;
                if (Existing.Peer == Packet.Peer && Existing.Server && Existing.Context)
                {
                    auto AliasId = Cid(Packet.Classification.ConnectionIdBytes.begin(),
                                       Packet.Classification.ConnectionIdBytes.end());
                    Entries_.emplace(
                        Key,
                        Entry{std::move(AliasId), Existing.Server, Existing.Peer, Existing.Context});
                    const auto Accepted = Existing.Server->ReceivePacket(Packet.Payload, Packet.Peer);
                    return Accepted;
                }
            }
            if (!Options_.Factory)
            {
                return false;
            }
            if (!Options_.Context || !Options_.Context->Ready())
            {
                return false;
            }
            auto Server = Options_.Factory(Packet.Classification.ConnectionIdBytes,
                                           Packet.Peer, Options_.Context);
            if (!Server || !Register(Cid(Packet.Classification.ConnectionIdBytes.begin(),
                                          Packet.Classification.ConnectionIdBytes.end()),
                                     Server, Packet.Peer, Options_.Context))
            {
                if (Server)
                {
                    Server->Close();
                }
                return false;
            }
            Server->Start();
            return Server->ReceivePacket(Packet.Payload, Packet.Peer);
        }

        [[nodiscard]] auto Remove(std::span<const std::byte> ConnectionId) -> bool
        {
            const auto It = Entries_.find(MakeKey(ConnectionId));
            if (It == Entries_.end())
            {
                return false;
            }
            It->second.Server->Close();
            Entries_.erase(It);
            return true;
        }

        auto Drain() noexcept -> void { Draining_ = true; }

        auto Close() noexcept -> void
        {
            Draining_ = true;
            Closed_ = true;
            for (auto &[Key, Entry] : Entries_)
            {
                (void)Key;
                Entry.Server->Close();
            }
            Entries_.clear();
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Entries_.size(); }

        [[nodiscard]] auto FindContext(std::span<const std::byte> ConnectionId) const
            -> SharedQuicAdmissionContext
        {
            const auto It = Entries_.find(MakeKey(ConnectionId));
            return It == Entries_.end() ? SharedQuicAdmissionContext{} : It->second.Context;
        }

    private:
        struct Entry final
        {
            Cid Id;
            std::shared_ptr<Preview::Quic::Server> Server;
            Udp::endpoint Peer;
            SharedQuicAdmissionContext Context;
        };

        [[nodiscard]] static auto MakeKey(std::span<const std::byte> ConnectionId) -> std::string
        {
            return std::string(reinterpret_cast<const char *>(ConnectionId.data()),
                               ConnectionId.size());
        }

        [[nodiscard]] static auto MakeKey(const Cid &ConnectionId) -> std::string
        {
            return MakeKey(std::span<const std::byte>(ConnectionId));
        }

        Options Options_;
        std::unordered_map<std::string, Entry> Entries_;
        bool Draining_{false};
        bool Closed_{false};
    };

} // namespace Preview::Ingress
