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
            std::vector<SharedQuicAdmissionContext> Contexts;
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
            Entries_.emplace(
                Key,
                Entry{std::move(ConnectionId),
                      std::vector<Candidate>{Candidate{std::move(Server), std::move(Context)}},
                      Peer});
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
                for (auto &[ExistingKey, Existing] : Entries_)
                {
                    (void)ExistingKey;
                    if (Existing.Peer == Packet.Peer)
                    {
                        return Dispatch(Existing, Packet.Payload, Packet.Peer);
                    }
                }
                return false;
            }
            const auto Key = MakeKey(Packet.Classification.ConnectionIdBytes);
            if (const auto It = Entries_.find(Key); It != Entries_.end())
            {
                return Dispatch(It->second, Packet.Payload, Packet.Peer);
            }
            // QUIC servers may advertise new destination CIDs during a live
            // connection. Keep those aliases attached to the existing server
            // owner; explicit Register still rejects peer conflicts so callers
            // cannot accidentally merge independent connections.
            for (const auto &[ExistingKey, Existing] : Entries_)
            {
                (void)ExistingKey;
                if (Existing.Peer == Packet.Peer && !Existing.Candidates.empty())
                {
                    auto AliasId = Cid(Packet.Classification.ConnectionIdBytes.begin(),
                                       Packet.Classification.ConnectionIdBytes.end());
                    Entries_.emplace(
                        Key,
                        Entry{std::move(AliasId), Existing.Candidates, Existing.Peer});
                    const auto It = Entries_.find(Key);
                    return It != Entries_.end() &&
                           Dispatch(It->second, Packet.Payload, Packet.Peer);
                }
            }
            if (!Options_.Factory)
            {
                return false;
            }
            for (const auto &[ExistingKey, Existing] : Entries_)
            {
                (void)ExistingKey;
                if (Existing.Peer == Packet.Peer)
                {
                    return false;
                }
            }

            const auto Contexts = AdmissionContexts();
            if (Contexts.size() != 1U)
            {
                // A shared listener must select one QUIC protocol before
                // passing bytes into ngtcp2. Trialing Hysteria2 and TUIC
                // engines with the same Initial/Handshake packet can corrupt
                // one engine while the other candidate is still alive.
                return false;
            }

            Entry NewEntry;
            NewEntry.Id = Cid(Packet.Classification.ConnectionIdBytes.begin(),
                               Packet.Classification.ConnectionIdBytes.end());
            NewEntry.Peer = Packet.Peer;
            for (const auto &Context : Contexts)
            {
                if (!Context || !Context->Ready())
                {
                    continue;
                }
                auto Server = Options_.Factory(Packet.Classification.ConnectionIdBytes,
                                               Packet.Peer, Context);
                if (Server)
                {
                    NewEntry.Candidates.push_back(Candidate{std::move(Server), Context});
                }
            }
            if (NewEntry.Candidates.empty())
            {
                return false;
            }
            const auto [It, Inserted] = Entries_.emplace(std::move(Key), std::move(NewEntry));
            if (!Inserted)
            {
                return false;
            }
            for (const auto &CandidateValue : It->second.Candidates)
            {
                CandidateValue.Server->Start();
            }
            return Dispatch(It->second, Packet.Payload, Packet.Peer);
        }

        [[nodiscard]] auto Remove(std::span<const std::byte> ConnectionId) -> bool
        {
            const auto It = Entries_.find(MakeKey(ConnectionId));
            if (It == Entries_.end())
            {
                return false;
            }
            CloseCandidates(It->second);
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
                CloseCandidates(Entry);
            }
            Entries_.clear();
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Entries_.size(); }

        [[nodiscard]] auto FindContext(std::span<const std::byte> ConnectionId) const
            -> SharedQuicAdmissionContext
        {
            const auto It = Entries_.find(MakeKey(ConnectionId));
            if (It == Entries_.end() || It->second.Candidates.empty())
            {
                return {};
            }
            return It->second.Candidates.front().Context;
        }

    private:
        struct Candidate final
        {
            std::shared_ptr<Preview::Quic::Server> Server;
            SharedQuicAdmissionContext Context;
        };

        struct Entry final
        {
            Cid Id;
            std::vector<Candidate> Candidates;
            Udp::endpoint Peer;
        };

        [[nodiscard]] auto AdmissionContexts() const
            -> std::vector<SharedQuicAdmissionContext>
        {
            if (!Options_.Contexts.empty())
            {
                return Options_.Contexts;
            }
            if (Options_.Context)
            {
                return {Options_.Context};
            }
            return {};
        }

        [[nodiscard]] static auto Dispatch(
            Entry &EntryValue,
            const std::span<const std::byte> Payload,
            const Udp::endpoint &Peer) -> bool
        {
            if (EntryValue.Peer != Peer)
            {
                return false;
            }
            bool Accepted = false;
            for (auto It = EntryValue.Candidates.begin(); It != EntryValue.Candidates.end();)
            {
                if (!It->Server || It->Server->Health().Closed)
                {
                    It = EntryValue.Candidates.erase(It);
                    continue;
                }
                Accepted = It->Server->ReceivePacket(Payload, Peer) || Accepted;
                if (It->Server->Health().Closed)
                {
                    It = EntryValue.Candidates.erase(It);
                }
                else
                {
                    ++It;
                }
            }
            return Accepted;
        }

        static auto CloseCandidates(Entry &EntryValue) noexcept -> void
        {
            for (auto &CandidateValue : EntryValue.Candidates)
            {
                if (CandidateValue.Server)
                {
                    CandidateValue.Server->Close();
                }
            }
            EntryValue.Candidates.clear();
        }

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
