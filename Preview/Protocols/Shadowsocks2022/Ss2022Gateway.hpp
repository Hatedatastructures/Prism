/** @file Ss2022Gateway.hpp @brief SS2022 raw UDP peer、账户租约、在途 I/O 及真实 drain owner。 */
#pragma once
#include <Preview/Protocols/Shadowsocks2022/Detail/Target.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Lifecycle/DrainBarrier.hpp>
#include <Preview/Lifecycle/DrainReservation.hpp>
#include <Preview/Protocols/Shadowsocks2022/GatewayState.hpp>
#include <Preview/Protocols/Shadowsocks2022/Prepared.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <openssl/rand.h>

#include <atomic>
#include <cstdint>
#include <unordered_map>
namespace Preview::Shadowsocks2022
{
    [[nodiscard]] inline auto MakeTrafficObservation(
        const std::shared_ptr<Preview::Foundation::TrafficSink>& Traffic, Preview::GenerationId Generation,
        Preview::AccountId Account) -> Preview::Foundation::TrafficObservation
    {
        return {Traffic, Preview::Foundation::TrafficEvent{.Generation = Generation, .Account = Account}};
    }

    class Ss2022Gateway final : public Preview::Contract::RawDatagramIngress,
                                public std::enable_shared_from_this<Ss2022Gateway>
    {
    public:
        /** @brief 接管同一 prepared credential 和服务；协议不拥有公共 socket。 */
        explicit Ss2022Gateway(std::shared_ptr<const Prepared> Value)
            : State_(std::make_shared<GatewayState>(std::move(Value)))
        {
        }
        ~Ss2022Gateway() override
        {
            State_->OwnerReleased();
        }
        /** @brief 严格借用密文，仅验证实际 wire，不保存输入或申请 quota/rate 租约。 */
        [[nodiscard]] auto Matches(Preview::Contract::DatagramView Packet) const -> bool override
        {
            if (State_->Closed.load())
                return false;
            if (auto Storage = State_->Storage.lock(); Storage && Storage->IsSealed())
                return false;
            return Parse(Packet.Payload).has_value();
        }

        /** @brief 只匹配已持有同一 peer/session/account/代次租约的 raw 关联。 */
        [[nodiscard]] auto MatchesExistingAssociation(
            Preview::Contract::DatagramView Packet) const -> bool override
        {
            if (State_->Closed.load(std::memory_order_acquire) ||
                State_->PeerRouteSnapshotUnavailable())
            {
                return false;
            }
            if (auto Storage = State_->Storage.lock(); Storage && Storage->IsSealed())
            {
                return false;
            }
            const auto Prepared = State_->Value.load(std::memory_order_acquire);
            const auto Routes = State_->PeerRoutes.load(std::memory_order_acquire);
            if (!Prepared || !Prepared->Input.Generation || !Routes || Routes->empty())
            {
                return false;
            }
            const auto Decoded = Parse(Packet.Payload);
            if (!Decoded)
            {
                return false;
            }
            const auto Binding = Decoded->Credential.Binding();
            if (!Binding)
            {
                return false;
            }
            const auto Account = Binding->AccountId();
            const auto Generation = Prepared->Input.Generation->Id();
            const auto BindingIdentity = reinterpret_cast<std::uintptr_t>(Binding.get());
            const auto MaterialIdentity = reinterpret_cast<std::uintptr_t>(
                &Decoded->Credential.Material());
            for (const auto& Route : *Routes)
            {
                if (Route.HasAccountLease && Route.HasGenerationUse &&
                    Route.Peer == Packet.Peer && Route.ClientSession == Decoded->Session &&
                    Route.Account == Account && Route.Generation == Generation &&
                    Route.CredentialBinding == BindingIdentity &&
                    Route.CredentialMaterial == MaterialIdentity)
                {
                    return true;
                }
            }
            return false;
        }
        /** @brief 接管包并在本 strand 注册在途任务；close 后直接拒绝，bad auth/replay 不触发 egress。 */
        auto Consume(Preview::Contract::DatagramPacket Packet) -> void override
        {
            if (auto Storage = State_->Storage.lock(); Storage && Storage->IsSealed())
                return;
            auto Admission = State_->PreparePacketAdmission(std::move(Packet));
            if (!Admission) return;
            const auto Self = shared_from_this();
            try
            {
                if (State_->Context && !State_->Context->CanDispatch())
                {
                    State_->BlockDispatch();
                    return;
                }
                Net::post(State_->Strand,
                    [Self, Admission = std::move(*Admission)]() mutable
                    {
                        Self->Start(std::move(Admission));
                    });
            }
            catch (...)
            {
                State_->BlockDispatch();
            }
        }
        /** @brief 任意线程封止，取消全部在途 DNS/egress/sender，最终清 peer 和账户租约。 */
        auto Close() noexcept -> void override
        {
            State_->Close();
        }
        /** @brief 暴露 GatewayState 的 closed+barrier 物理退休事实，不读取公开 Drain 错误。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return State_->IsRetired();
        }

        /** @brief 从 PeerRoute 原子快照读取仍持 account 与 generation lease 的关联。 */
        [[nodiscard]] auto HasActiveAssociations() const noexcept -> bool override
        {
            if (State_->PeerRouteSnapshotUnavailable())
            {
                return true;
            }
            const auto Prepared = State_->Value.load(std::memory_order_acquire);
            const auto Routes = State_->PeerRoutes.load(std::memory_order_acquire);
            if (!Prepared || !Prepared->Input.Generation || !Routes)
            {
                return false;
            }
            const auto Generation = Prepared->Input.Generation->Id();
            for (const auto& Route : *Routes)
            {
                if (Route.HasAccountLease && Route.HasGenerationUse && Route.Account &&
                    Route.Generation == Generation && Route.CredentialBinding != 0 &&
                    Route.CredentialMaterial != 0)
                {
                    return true;
                }
            }
            return false;
        }
        /** @brief 在协议 strand 等待取消后的实际 coroutine completion；无 half-close。 */
        auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            Close();
            if (State_->Context && !State_->Context->CanDispatch())
            {
                State_->BlockDispatch();
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            co_return co_await Net::co_spawn(State_->Strand, DrainOnStrand(shared_from_this()), Net::use_awaitable);
        }

    private:
        struct Parsed final
        {
            Preview::Protocols::ScopedMaterial Credential;
            Address Target;
            std::vector<std::uint8_t> Payload;
            boost::asio::ip::udp::endpoint Peer;
            std::array<std::uint8_t, SessionIdLen> Session{};
            std::uint64_t PacketId{0};
        };
        using PeerState = GatewayState::PeerState;
        using Operation = GatewayState::Operation;
        [[nodiscard]] auto Parse(std::span<const std::byte> Payload) const -> std::optional<Parsed>
        {
            const auto Value = State_->Value.load();
            if (!Value)
                return {};
            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(Payload.data()), Payload.size());
            for (const auto& Record : Value->Credentials)
            {
                Parsed Result;
                Result.Credential = Record;
                const auto Key = WireKey(Record);
                std::uint8_t Type = HeaderTypeClient;
                const auto ErrorValue =
                    ParseUdpPacket(UdpParseInput{Key, Bytes, &Result.Target, &Result.Payload, &Result.Session,
                        &Result.PacketId, nullptr, &Type, nullptr, 0, Value->Input.Config.TimeWindow});
                if (ErrorValue == Preview::Error::None && Type == HeaderTypeClient)
                    return Result;
            }
            return {};
        }
        [[nodiscard]] static auto PeerKey(const Preview::Contract::DatagramPacket& Packet) -> std::string
        {
            return Packet.Peer.address().to_string() + ":" + std::to_string(Packet.Peer.port());
        }
        [[nodiscard]] static auto AcceptId(PeerState& Peer, std::uint64_t Id) -> bool
        {
            if (!Peer.ReplayBits)
            {
                Peer.Highest = Id;
                Peer.ReplayBits = 1;
                return true;
            }
            if (Id > Peer.Highest)
            {
                const auto Shift = Id - Peer.Highest;
                if (Shift >= 64)
                {
                    Peer.ReplayBits = 1;
                }
                else
                {
                    Peer.ReplayBits = (Peer.ReplayBits << Shift) | 1;
                }
                Peer.Highest = Id;
                return true;
            }
            const auto Distance = Peer.Highest - Id;
            if (Distance >= 64 || (Peer.ReplayBits & (1ULL << Distance)))
                return false;
            Peer.ReplayBits |= 1ULL << Distance;
            return true;
        }
        [[nodiscard]] auto Admit(const std::string& Name, const Parsed& Packet,
            Preview::Foundation::GenerationUseLease &GenerationUse) -> bool
        {
            bool AssociationChanged = Reap();
            const auto Reject = [this, &AssociationChanged]() -> bool
            {
                if (AssociationChanged)
                {
                    (void)State_->PublishPeerRoutes();
                }
                return false;
            };
            auto Found = State_->Peers.find(Name);
            if (Found != State_->Peers.end() && (Found->second.Credential.Binding() != Packet.Credential.Binding() ||
                &Found->second.Credential.Material() != &Packet.Credential.Material()))
            {
                return Reject();
            }
            if (Found == State_->Peers.end() || Found->second.ClientSession != Packet.Session)
            {
                if (!GenerationUse)
                {
                    return Reject();
                }
                if (Found == State_->Peers.end() &&
                    State_->Peers.size() >= State_->Value.load()->Input.Config.MaxPeers)
                {
                    return Reject();
                }
                PeerState State;
                State.Credential = Packet.Credential;
                State.Peer = Packet.Peer;
                State.ClientSession = Packet.Session;
                if (RAND_bytes(State.ServerSession.data(), State.ServerSession.size()) != 1)
                {
                    return Reject();
                }
                auto Auth = State_->Value.load()->Services.Authentication.Authenticator->Authenticate(
                    Preview::AuthenticationRequest{.AccountId = Packet.Credential.Binding()->AccountId(),
                        .Credential = Packet.Credential.Material().Credential.View()});
                if (!Auth || Auth->AccountId() != Packet.Credential.Binding()->AccountId())
                {
                    return Reject();
                }
                State.Lease = std::move(*Auth);
                State.GenerationUse = std::move(GenerationUse);
                State_->BeginPeerRouteMutation();
                try
                {
                    if (Found != State_->Peers.end())
                    {
                        State_->Peers.erase(Found);
                    }
                    Found = State_->Peers.emplace(Name, std::move(State)).first;
                }
                catch (...)
                {
                    State_->BlockDispatch();
                    return false;
                }
                AssociationChanged = true;
            }
            Found->second.LastSeen = std::chrono::steady_clock::now();
            const auto Accepted = AcceptId(Found->second, Packet.PacketId);
            if (AssociationChanged && !State_->PublishPeerRoutes())
            {
                return false;
            }
            return Accepted;
        }
        auto Start(GatewayState::PacketAdmission Admission) -> void
        {
            if (State_->Closed.load())
                return;
            const auto Id = State_->NextOperation++;
            try
            {
                auto Work = std::make_shared<Operation>(std::move(Admission));
                State_->Active.emplace(Id, Work);
                const auto Self = shared_from_this();
                Net::co_spawn(State_->Strand, Self->Process(Work),
                    Net::bind_cancellation_slot(Work->Cancellation.slot(),
                        [Self, Id, Work](std::exception_ptr) { Self->State_->Active.erase(Id); }));
            }
            catch (...)
            {
                State_->Active.erase(Id);
                State_->Barrier.Block();
            }
        }
        auto Process(std::shared_ptr<Operation> Work) -> Net::awaitable<void>
        {
            const auto Value = State_->Value.load();
            const auto &Packet = Work->Admission.Packet();
            auto Decoded = Parse(Packet.Payload);
            if (Decoded) Decoded->Peer = Packet.Peer;
            const auto Name = PeerKey(Packet);
            if (!Decoded || !Admit(Name, *Decoded, Work->Admission.Packet().GenerationUse))
                co_return;
            Preview::Contract::DatagramExchangeRequest Request;
            auto Target = Preview::Shadowsocks2022::Detail::ToNetworkTarget(Decoded->Target);
            if (!Target) co_return;
            Request.Target = std::move(*Target);
            Request.AccountId = Decoded->Credential.Binding()->AccountId();
            Request.Timeout = Value->Input.Config.RelayTimeout;
            Request.Payload.resize(Decoded->Payload.size());
            std::memcpy(Request.Payload.data(), Decoded->Payload.data(), Decoded->Payload.size());
            auto Response = co_await Value->Services.Egress->Exchange(std::move(Request));
            if (State_->Closed.load() || Response.Failure.Failed())
                co_return;
            auto Found = State_->Peers.find(Name);
            if (Found == State_->Peers.end() || Found->second.ClientSession != Decoded->Session)
                co_return;
            auto SourceType = AddressType::Ipv6;
            if (Response.Source.address().is_v4())
            {
                SourceType = AddressType::Ipv4;
            }
            Address Source{SourceType,
                Response.Source.address().to_string(), Response.Source.port()};
            const auto Key = WireKey(Found->second.Credential);
            std::vector<std::uint8_t> Wire;
            if (!BuildUdpPacket(UdpBuildInput{Key, Found->second.NextPacket++, &Source,
                                    std::span<const std::uint8_t>(
                                        reinterpret_cast<const std::uint8_t*>(Response.Payload.data()),
                                        Response.Payload.size()),
                                    Found->second.ServerSession, 0, Found->second.ClientSession,
                                    HeaderTypeServer},
                    Wire))
                co_return;
            const auto Downloaded = Response.Payload.size();
            Preview::Contract::DatagramPacket Output{{}, Packet.Peer, Packet.Sequence};
            Output.Payload.resize(Wire.size());
            std::memcpy(Output.Payload.data(), Wire.data(), Wire.size());
            const auto Sent = co_await Value->Services.Sender->Send(std::move(Output));
            if (!Sent && Value->Services.Traffic)
            {
                try
                {
                    auto Generation = Preview::GenerationId{};
                    if (Value->Input.Generation)
                    {
                        Generation = Value->Input.Generation->Id();
                    }
                    auto Observation = MakeTrafficObservation(Value->Services.Traffic,
                        Generation,
                        Decoded->Credential.Binding()->AccountId());
                    Observation.Transfer(Response.Uploaded,
                        Preview::Foundation::TrafficObservation::Direction::Upload);
                    Observation.Transfer(Downloaded,
                        Preview::Foundation::TrafficObservation::Direction::Download);
                }
                catch (...)
                {
                }
            }
        }
        [[nodiscard]] auto Reap() -> bool
        {
            const auto Now = std::chrono::steady_clock::now();
            bool AssociationChanged = false;
            for (auto It = State_->Peers.begin(); It != State_->Peers.end();)
            {
                if (Now - It->second.LastSeen > State_->Value.load()->Input.Config.PeerIdleTimeout)
                {
                    if (!AssociationChanged)
                    {
                        State_->BeginPeerRouteMutation();
                    }
                    It = State_->Peers.erase(It);
                    AssociationChanged = true;
                }
                else
                {
                    ++It;
                }
            }
            return AssociationChanged;
        }
        static auto DrainOnStrand(std::shared_ptr<Ss2022Gateway> Self)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            const auto Drained = co_await Self->State_->Barrier.Drain();
            if (!Drained) co_return std::unexpected(Drained.error());
            if (const auto Value = Self->State_->Value.load())
            {
                auto Generation = Preview::GenerationId{};
                if (Value->Input.Generation)
                {
                    Generation = Value->Input.Generation->Id();
                }
                MakeTrafficObservation(Value->Services.Traffic,
                    Generation,
                    Preview::AccountId{})
                    .Complete();
            }
            Self->State_->Value.store({});
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        std::shared_ptr<GatewayState> State_;
    };
} // namespace Preview::Shadowsocks2022
