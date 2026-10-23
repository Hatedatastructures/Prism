/** @file GatewayProcess.cpp @brief SS2022 UDP gateway 数据面实现。 */
#include <Prism/Protocols/Shadowsocks2022/Ss2022Gateway.hpp>
#include <Prism/Protocols/Shadowsocks2022/GatewayState.hpp>

#include "Detail/Target.hpp"
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <openssl/rand.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Prism::Shadowsocks2022
{

    auto Ss2022Gateway::Process(std::shared_ptr<Operation> Work) -> Net::awaitable<void>
    {
        if (State_->Closed.load(std::memory_order_acquire))
        {
            co_return;
        }
        const auto Value = State_->Value.load();
        const auto& Packet = Work->Admission.Packet();
        auto Decoded = Parse(Packet.Payload);
        if (Decoded)
        {
            Decoded->Peer = Packet.Peer;
        }
        const auto Name = PeerKey(Packet);
        if (!Decoded)
        {
            co_return;
        }
        auto GenerationUse = Work->Admission.TakeGenerationUseLease();
        if (!Admit(Name, *Decoded, GenerationUse))
        {
            co_return;
        }

        Prism::Contract::DatagramExchangeRequest Request;
        auto Target = Detail::ToNetworkTarget(Decoded->Target);
        if (!Target)
        {
            co_return;
        }
        Request.Target = std::move(*Target);
        Request.AccountId = Decoded->Credential.Binding()->AccountId();
        Request.Timeout = Value->Input.Config.RelayTimeout;
        Request.Payload.resize(Decoded->Payload.size());
        std::memcpy(Request.Payload.data(), Decoded->Payload.data(), Decoded->Payload.size());
        auto Response = co_await Value->Services.Egress->Exchange(std::move(Request));
        if (State_->Closed.load() || Response.Failure.Failed())
        {
            co_return;
        }

        auto Found = State_->Peers.find(Name);
        if (Found == State_->Peers.end() || Found->second.ClientSession != Decoded->Session)
        {
            co_return;
        }
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
                HeaderTypeServer}, Wire))
        {
            co_return;
        }

        const auto Downloaded = Response.Payload.size();
        Prism::Contract::DatagramPacket Output{{}, Packet.Peer, Packet.Sequence};
        Output.Payload.resize(Wire.size());
        std::memcpy(Output.Payload.data(), Wire.data(), Wire.size());
        const auto Sent = co_await Value->Services.Sender->Send(std::move(Output));
        if (!Sent && Value->Services.Traffic)
        {
            try
            {
                auto Generation = Prism::GenerationId{};
                if (Value->Input.Generation)
                {
                    Generation = Value->Input.Generation->Id();
                }
                auto Observation = MakeTrafficObservation(Value->Services.Traffic,
                    Generation, Decoded->Credential.Binding()->AccountId());
                Observation.Transfer(Response.Uploaded,
                    Prism::Foundation::TrafficObservation::Direction::Upload);
                Observation.Transfer(Downloaded,
                    Prism::Foundation::TrafficObservation::Direction::Download);
            }
            catch (...)
            {
            }
        }
    }



    [[nodiscard]] auto MakeTrafficObservation(
        const std::shared_ptr<Prism::Foundation::TrafficSink>& Traffic, Prism::GenerationId Generation,
        Prism::AccountId Account) -> Prism::Foundation::TrafficObservation
    {
        return {Traffic, Prism::Foundation::TrafficEvent{.Generation = Generation, .Account = Account}};
    }

    Ss2022Gateway::Ss2022Gateway(std::shared_ptr<const Prepared> Value)
        : State_(std::make_shared<GatewayState>(std::move(Value)))
    {
    }

    Ss2022Gateway::~Ss2022Gateway()
    {
        State_->OwnerReleased();
    }

    [[nodiscard]] auto Ss2022Gateway::Matches(Prism::Contract::DatagramView Packet) const -> bool
    {
        if (State_->Closed.load())
            return false;
        if (auto Storage = State_->Storage.lock(); Storage && Storage->IsSealed())
            return false;
        return Parse(Packet.Payload).has_value();
    }

    [[nodiscard]] auto Ss2022Gateway::MatchesExistingAssociation(
        Prism::Contract::DatagramView Packet) const -> bool
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

    auto Ss2022Gateway::Consume(Prism::Contract::DatagramPacket Packet) -> void
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

    auto Ss2022Gateway::Close() noexcept -> void
    {
        State_->Close();
    }

    [[nodiscard]] auto Ss2022Gateway::IsRetired() const noexcept -> bool
    {
        return State_->IsRetired();
    }

    [[nodiscard]] auto Ss2022Gateway::HasActiveAssociations() const noexcept -> bool
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

    auto Ss2022Gateway::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Close();
        if (State_->Context && !State_->Context->CanDispatch())
        {
            State_->DeferDispatch();
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return co_await Net::co_spawn(State_->Strand, DrainOnStrand(shared_from_this()), Net::use_awaitable);
    }

    [[nodiscard]] auto Ss2022Gateway::Parse(std::span<const std::byte> Payload) const -> std::optional<Parsed>
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
            if (ErrorValue == Prism::Error::None && Type == HeaderTypeClient)
                return Result;
        }
        return {};
    }

    [[nodiscard]] auto Ss2022Gateway::PeerKey(const Prism::Contract::DatagramPacket& Packet) -> std::string
    {
        return Packet.Peer.address().to_string() + ":" + std::to_string(Packet.Peer.port());
    }

    [[nodiscard]] auto Ss2022Gateway::AcceptId(PeerState& Peer, std::uint64_t Id) -> bool
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

    [[nodiscard]] auto Ss2022Gateway::Admit(const std::string& Name, const Parsed& Packet,
        Prism::Foundation::GenerationUseLease &GenerationUse) -> bool
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
                Prism::AuthenticationRequest{.AccountId = Packet.Credential.Binding()->AccountId(),
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

    auto Ss2022Gateway::Start(GatewayState::PacketAdmission Admission) -> void
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

    [[nodiscard]] auto Ss2022Gateway::Reap() -> bool
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

    auto Ss2022Gateway::DrainOnStrand(std::shared_ptr<Ss2022Gateway> Self)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Drained = co_await Self->State_->Barrier.Drain();
        if (!Drained) co_return std::unexpected(Drained.error());
        if (const auto Value = Self->State_->Value.load())
        {
            auto Generation = Prism::GenerationId{};
            if (Value->Input.Generation)
            {
                Generation = Value->Input.Generation->Id();
            }
            MakeTrafficObservation(Value->Services.Traffic,
                Generation,
                Prism::AccountId{})
                .Complete();
        }
        Self->State_->Value.store({});
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    GatewayState::GatewayState(std::shared_ptr<const Prepared> PreparedValue)
        : Context(Prism::Executor::ContextOwner::Find(PreparedValue->Services.Executor)),
          Storage(Prism::Executor::ContextOwner::Storage(PreparedValue->Services.Executor)),
          Value(std::move(PreparedValue)), Strand(Net::make_strand(Value.load()->Services.Executor)),
          Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(Strand)), Barrier(Reclaimer)
    {
    }

    GatewayState::PacketBudget::PacketBudget(PacketBudget &&Other) noexcept
        : Pending_(std::exchange(Other.Pending_, nullptr))
    {
    }

    GatewayState::PacketBudget::~PacketBudget() noexcept
    {
        Release();
    }

    auto GatewayState::PacketBudget::Release() noexcept -> void
    {
        if (Pending_ == nullptr)
        {
            return;
        }
        Pending_->fetch_sub(1U, std::memory_order_acq_rel);
        Pending_ = nullptr;
    }

    GatewayState::PacketBudget::PacketBudget(std::atomic<std::size_t> *Pending)
        : Pending_(Pending)
    {
    }

    GatewayState::PacketReservation::PacketReservation(
        PacketReservation &&Other) noexcept
        : Owner_(std::move(Other.Owner_)), Activity_(std::move(Other.Activity_)),
          Budget_(std::move(Other.Budget_)),
          Completed_(std::exchange(Other.Completed_, true))
    {
    }

    GatewayState::PacketReservation::PacketReservation(
        std::shared_ptr<GatewayState> Owner,
        Prism::Lifecycle::DrainReservation Activity,
        PacketBudget Budget)
        : Owner_(std::move(Owner)), Activity_(std::move(Activity)),
          Budget_(std::move(Budget)), Completed_(false)
    {
    }

    GatewayState::PacketAdmission::PacketAdmission(PacketAdmission &&Other) noexcept
        : Reservation_(std::move(Other.Reservation_)), Packet_(std::move(Other.Packet_))
    {
    }

    GatewayState::PacketAdmission::PacketAdmission(
        Prism::Contract::DatagramPacket Packet,
        PacketReservation Reservation)
        : Reservation_(std::move(Reservation)), Packet_(std::move(Packet))
    {
    }

    auto GatewayState::Close() noexcept -> void
    {
        std::optional<Prism::Lifecycle::DrainReservation> Reservation;
        if (Barrier.Enter())
            Reservation.emplace(Barrier);
        if (Closed.exchange(true))
            return;
        if (Reservation)
            Ticket_->Reservation.emplace(std::move(*Reservation));
        Barrier.Seal();
        RequestRetirement();
    }

    auto GatewayState::OwnerReleased() noexcept -> void
    {
        Close();
        if (IsRetired())
            return;
        if (Context && !Context->CanDispatch())
            DeferDispatch();
        if (auto Owner = Storage.lock())
            Owner->Retain(shared_from_this());
    }

    auto GatewayState::RequestRetirement() noexcept -> void
    {
        if (Finalized_.load() || Scheduled_.exchange(true))
            return;
        if (Context && !Context->CanDispatch())
        {
            Scheduled_.store(false);
            DeferDispatch();
            return;
        }
        try
        {
            const auto Self = shared_from_this();
            if (Reclaimer->Post([Self] { Self->CloseOnStrand(); }))
                return;
        }
        catch (...)
        {
        }
        Scheduled_.store(false);
        if (Context && !Context->CanDispatch())
            DeferDispatch();
        else
            BlockDispatch();
    }

    [[nodiscard]] auto GatewayState::IsRetired() const noexcept -> bool
    {
        return ResourcesReleased_.load() && Barrier.Active() == 0 && !Barrier.IsBlocked();
    }

    [[nodiscard]] auto GatewayState::IsDispatchUnavailable() const noexcept -> bool
    {
        return DispatchFailed_.load();
    }

    [[nodiscard]] auto GatewayState::PreparePacketAdmission(
        Prism::Contract::DatagramPacket Packet) -> std::optional<PacketAdmission>
    {
        const auto Owner = weak_from_this().lock();
        if (!Owner) return std::nullopt;
        auto Budget = ReservePacket();
        if (!Budget) return std::nullopt;
        if (!Barrier.Enter()) return std::nullopt;
        Prism::Lifecycle::DrainReservation Activity(Barrier);
        auto Reservation = PacketReservation(
            Owner, std::move(Activity), std::move(*Budget));
        return PacketAdmission(std::move(Packet), std::move(Reservation));
    }

    [[nodiscard]] auto GatewayState::ReservePacket() noexcept -> std::optional<PacketBudget>
    {
        auto Active = PendingPackets.load(std::memory_order_acquire);
        while (Active < MaxPendingPackets)
        {
            if (PendingPackets.compare_exchange_weak(
                    Active, Active + 1U, std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return PacketBudget(&PendingPackets);
            }
        }
        return std::nullopt;
    }

    auto GatewayState::PublishPeerRoutes() noexcept -> bool
    {
        if (Peers.empty())
        {
            PeerRoutes.store({}, std::memory_order_release);
            PeerRouteSnapshotUnavailable_.store(false, std::memory_order_release);
            return true;
        }
        try
        {
            const auto Prepared = Value.load(std::memory_order_acquire);
            if (!Prepared || !Prepared->Input.Generation)
            {
                PeerRoutes.store({}, std::memory_order_release);
                PeerRouteSnapshotUnavailable_.store(true, std::memory_order_release);
                BlockDispatch();
                return false;
            }
            const auto Generation = Prepared->Input.Generation->Id();
            auto Routes = std::make_shared<PeerRouteTable>();
            Routes->reserve(Peers.size());
            for (const auto& Entry : Peers)
            {
                const auto& Peer = Entry.second;
                const auto Binding = Peer.Credential.Binding();
                const auto AccountBinding = Peer.Lease.Binding();
                if (!Peer.Credential || !Binding || !AccountBinding || AccountBinding != Binding)
                {
                    continue;
                }
                const auto Account = Peer.Lease.AccountId();
                const auto HasAccountLease = static_cast<bool>(Peer.Lease);
                const auto HasGenerationUse = static_cast<bool>(Peer.GenerationUse);
                const auto BindingIdentity = reinterpret_cast<std::uintptr_t>(Binding.get());
                const auto MaterialIdentity = reinterpret_cast<std::uintptr_t>(
                    &Peer.Credential.Material());
                if (!Account || !Generation || !HasAccountLease || !HasGenerationUse ||
                    Binding->AccountId() != Account || BindingIdentity == 0 || MaterialIdentity == 0)
                {
                    continue;
                }
                Routes->push_back(PeerRoute{
                    .Peer = Peer.Peer,
                    .CredentialBinding = BindingIdentity,
                    .CredentialMaterial = MaterialIdentity,
                    .Account = Account,
                    .Generation = Generation,
                    .ClientSession = Peer.ClientSession,
                    .HasAccountLease = HasAccountLease,
                    .HasGenerationUse = HasGenerationUse});
            }
            PeerRoutes.store(std::move(Routes), std::memory_order_release);
            PeerRouteSnapshotUnavailable_.store(false, std::memory_order_release);
            return true;
        }
        catch (...)
        {
            PeerRoutes.store({}, std::memory_order_release);
            PeerRouteSnapshotUnavailable_.store(true, std::memory_order_release);
            BlockDispatch();
            return false;
        }
    }

    auto GatewayState::BeginPeerRouteMutation() noexcept -> void
    {
        PeerRouteSnapshotUnavailable_.store(true, std::memory_order_release);
    }

    [[nodiscard]] auto GatewayState::PeerRouteSnapshotUnavailable() const noexcept -> bool
    {
        return PeerRouteSnapshotUnavailable_.load(std::memory_order_acquire);
    }

    auto GatewayState::BlockDispatch() noexcept -> void
    {
        Barrier.Block();
        DispatchFailed_.store(true);
        if (auto Owner = Storage.lock())
            Owner->Retain(shared_from_this());
    }

    auto GatewayState::DeferDispatch() noexcept -> void
    {
        DispatchFailed_.store(true);
        if (auto Owner = Storage.lock())
            Owner->Retain(shared_from_this());
    }

    auto GatewayState::CloseOnStrand() noexcept -> void
    {
        auto Closing = std::move(Active);
        Active.clear();
        for (const auto& [Id, Work] : Closing)
        {
            try
            {
                Work->Cancellation.emit(Net::cancellation_type::all);
            }
            catch (...)
            {
                Barrier.Block();
            }
        }
        BeginPeerRouteMutation();
        Peers.clear();
        PeerRoutes.store({}, std::memory_order_release);
        PeerRouteSnapshotUnavailable_.store(false, std::memory_order_release);
        Finalized_.store(true);
        Ticket_->Reservation.reset();
        ReleasePrepared();
    }

    auto GatewayState::ReleasePrepared() noexcept -> void
    {
        if (!Finalized_.load() || Barrier.Active() != 0 || Barrier.IsBlocked())
            return;
        Value.store({});
        ResourcesReleased_.store(true);
    }

    auto GatewayState::RequestPreparedRelease() noexcept -> void
    {
        if (!Finalized_.load() || Barrier.Active() != 0 || Barrier.IsBlocked())
            return;
        if (Strand.running_in_this_thread())
        {
            ReleasePrepared();
            return;
        }
        try
        {
            const auto Owner = shared_from_this();
            if (Reclaimer->Post(PreparedRelease{Owner}))
                return;
        }
        catch (...)
        {
        }
        BlockDispatch();
    }

    auto GatewayState::PreparedRelease::operator()() const noexcept -> void { Owner->ReleasePrepared(); }

    auto GatewayState::PreparedRelease::OnQuarantine() const noexcept -> void { Owner->BlockDispatch(); }

    GatewayState::PacketReservation::~PacketReservation() noexcept
    {
        Complete();
    }

    auto GatewayState::PacketReservation::Complete() noexcept -> void
    {
        if (Completed_) return;
        Completed_ = true;
        if (!Owner_)
        {
            Budget_.Release();
            return;
        }
        Activity_.Transfer();
        Owner_->Barrier.Leave();
        Budget_.Release();
        Owner_->RequestPreparedRelease();
        Owner_.reset();
    }

} // namespace Prism::Shadowsocks2022
