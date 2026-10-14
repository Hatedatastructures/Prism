/** @file GatewayState.hpp @brief raw UDP 实物、实际 I/O 屏障及原 executor 关闭所有者。 */
#pragma once
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Lifecycle/CloseFailure.hpp>
#include <Preview/Lifecycle/DrainReservation.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Protocols/Shadowsocks2022/Prepared.hpp>

#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/strand.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>
namespace Preview::Shadowsocks2022
{
    /** @brief 接入前构造的关闭槽位；不引用 binding/gateway，L1 只保存本实物。 */
    class GatewayState final : public Preview::Executor::ClosingResource,
                               public std::enable_shared_from_this<GatewayState>
    {
        struct CloseTicket final
        {
            std::optional<Preview::Lifecycle::DrainReservation> Reservation;
        };

    public:
        /** @brief Fire-and-forget 接入的有界在途包预算；超限 UDP 包按丢包语义拒绝。 */
        static constexpr std::size_t MaxPendingPackets = 128U;

        class PacketBudget final
        {
        public:
            PacketBudget() = default;
            PacketBudget(const PacketBudget &) = delete;
            auto operator=(const PacketBudget &) -> PacketBudget & = delete;
            PacketBudget(PacketBudget &&Other) noexcept
                : Pending_(std::exchange(Other.Pending_, nullptr))
            {
            }
            auto operator=(PacketBudget &&Other) noexcept -> PacketBudget & = delete;
            ~PacketBudget() noexcept { Release(); }
            /** @brief 在 packet 退栈时先归还预算，再评估 owner 是否可释放。 */
            auto Release() noexcept -> void
            {
                if (Pending_ == nullptr) return;
                Pending_->fetch_sub(1U, std::memory_order_acq_rel);
                Pending_ = nullptr;
            }
        private:
            friend class GatewayState;
            explicit PacketBudget(std::atomic<std::size_t> *Pending)
                : Pending_(Pending)
            {
            }
            std::atomic<std::size_t> *Pending_{nullptr};
        };

        /** @brief 持有 raw datagram 的活动预约、包预算及真实 GatewayState owner。 */
        class PacketReservation final
        {
        public:
            PacketReservation(const PacketReservation &) = delete;
            auto operator=(const PacketReservation &) -> PacketReservation & = delete;
            PacketReservation(PacketReservation &&Other) noexcept
                : Owner_(std::move(Other.Owner_)), Activity_(std::move(Other.Activity_)),
                  Budget_(std::move(Other.Budget_)),
                  Completed_(std::exchange(Other.Completed_, true))
            {
            }
            auto operator=(PacketReservation &&Other) noexcept -> PacketReservation & = delete;
            ~PacketReservation() noexcept;

        private:
            friend class GatewayState;
            PacketReservation(std::shared_ptr<GatewayState> Owner,
                Preview::Lifecycle::DrainReservation Activity,
                PacketBudget Budget)
                : Owner_(std::move(Owner)), Activity_(std::move(Activity)),
                  Budget_(std::move(Budget)), Completed_(false)
            {
            }
            auto Complete() noexcept -> void;

            std::shared_ptr<GatewayState> Owner_;
            Preview::Lifecycle::DrainReservation Activity_;
            PacketBudget Budget_;
            bool Completed_{true};
        };

        /** @brief 一次 raw UDP 入队/运行资格，统一持有真实 DrainBarrier 与包预算预留。 */
        class PacketAdmission final
        {
        public:
            PacketAdmission(const PacketAdmission &) = delete;
            auto operator=(const PacketAdmission &) -> PacketAdmission & = delete;
            PacketAdmission(PacketAdmission &&Other) noexcept
                : Reservation_(std::move(Other.Reservation_)), Packet_(std::move(Other.Packet_))
            {
            }
            auto operator=(PacketAdmission &&Other) noexcept -> PacketAdmission & = delete;
            [[nodiscard]] auto Packet() noexcept -> Preview::Contract::DatagramPacket &
            {
                return Packet_;
            }
            [[nodiscard]] auto Packet() const noexcept
                -> const Preview::Contract::DatagramPacket &
            {
                return Packet_;
            }

        private:
            friend class GatewayState;
            PacketAdmission(Preview::Contract::DatagramPacket Packet,
                PacketReservation Reservation)
                : Reservation_(std::move(Reservation)), Packet_(std::move(Packet))
            {
            }

            PacketReservation Reservation_;
            Preview::Contract::DatagramPacket Packet_;
        };

        struct PeerRoute final
        {
            boost::asio::ip::udp::endpoint Peer;
            std::uintptr_t CredentialBinding{0};
            std::uintptr_t CredentialMaterial{0};
            Preview::AccountId Account;
            Preview::GenerationId Generation;
            std::array<std::uint8_t, SessionIdLen> ClientSession{};
            bool HasAccountLease{false};
            bool HasGenerationUse{false};
        };

        using PeerRouteTable = std::vector<PeerRoute>;

        struct PeerState final
        {
            Preview::Protocols::ScopedMaterial Credential;
            Preview::Account::AccountLease Lease;
            Preview::Foundation::GenerationUseLease GenerationUse;
            boost::asio::ip::udp::endpoint Peer;
            std::array<std::uint8_t, SessionIdLen> ClientSession{}, ServerSession{};
            std::uint64_t Highest{0}, ReplayBits{0}, NextPacket{0};
            std::chrono::steady_clock::time_point LastSeen;
        };
        struct Operation final
        {
            /** @brief 接管 owning 数据报与完整准入票据至任务 completion。 */
            explicit Operation(PacketAdmission AdmissionValue)
                : Admission(std::move(AdmissionValue))
            {
            }
            PacketAdmission Admission;
            Net::cancellation_signal Cancellation;
        };
        explicit GatewayState(std::shared_ptr<const Prepared> PreparedValue)
            : Context(Preview::Executor::ContextOwner::Find(PreparedValue->Services.Executor)),
              Storage(Preview::Executor::ContextOwner::Storage(PreparedValue->Services.Executor)),
              Value(std::move(PreparedValue)), Strand(Net::make_strand(Value.load()->Services.Executor)),
              Reclaimer(std::make_shared<Preview::Executor::ExecutorReclaimer>(Strand)), Barrier(Reclaimer)
        {
        }
        /** @brief 任意线程先预约 finalizer 再封止；关闭与 peer lease 释放只能在原 strand。 */
        auto Close() noexcept -> void
        {
            std::optional<Preview::Lifecycle::DrainReservation> Reservation;
            if (Barrier.Enter())
                Reservation.emplace(Barrier);
            if (Closed.exchange(true))
                return;
            if (Reservation)
                Ticket_->Reservation.emplace(std::move(*Reservation));
            Barrier.Seal();
            RequestRetirement();
        }
        /** @brief 最后 gateway owner 释放时保存尚未执行的 finalizer，反向联系不保留 gateway。 */
        auto OwnerReleased() noexcept -> void
        {
            Close();
            if (IsRetired())
                return;
            if (Context && !Context->CanDispatch())
                BlockDispatch();
            if (auto Owner = Storage.lock())
                Owner->Retain(shared_from_this());
        }
        /** @brief 沿唯一 reclaimer 请求回收；不可投递时保留同一个预构造实物到 L1。 */
        auto RequestRetirement() noexcept -> void override
        {
            if (Finalized_.load() || Scheduled_.exchange(true))
                return;
            try
            {
                const auto Self = shared_from_this();
                if ((!Context || Context->CanDispatch()) &&
                    Reclaimer->Post([Self] { Self->CloseOnStrand(); }))
                    return;
            }
            catch (...)
            {
            }
            Scheduled_.store(false);
            BlockDispatch();
        }
        /** @brief 关闭 finalizer 和所有真实 I/O 预约均完成才退休；Closed 标记不能代替此事实。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return ResourcesReleased_.load() && Barrier.Active() == 0 && !Barrier.IsBlocked();
        }
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return DispatchFailed_.load();
        }

        /** @brief 以真实活动预约和有界包预算取得一次 owning packet 准入资格。 */
        [[nodiscard]] auto PreparePacketAdmission(
            Preview::Contract::DatagramPacket Packet) -> std::optional<PacketAdmission>
        {
            const auto Owner = weak_from_this().lock();
            if (!Owner) return std::nullopt;
            auto Budget = ReservePacket();
            if (!Budget) return std::nullopt;
            if (!Barrier.Enter()) return std::nullopt;
            Preview::Lifecycle::DrainReservation Activity(Barrier);
            auto Reservation = PacketReservation(
                Owner, std::move(Activity), std::move(*Budget));
            return PacketAdmission(std::move(Packet), std::move(Reservation));
        }

    private:
        /** @brief 仅由准入票据申请；成功后由同一票据持有直到真实退栈。 */
        [[nodiscard]] auto ReservePacket() noexcept -> std::optional<PacketBudget>
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

    public:

        /** @brief 在 gateway strand 发布带 peer/account/generation lease 回执的只读快照。 */
        auto PublishPeerRoutes() noexcept -> bool
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
        /** @brief 在修改 strand peer map 前封止过期快照读，提交新快照后重新开放。 */
        auto BeginPeerRouteMutation() noexcept -> void
        {
            PeerRouteSnapshotUnavailable_.store(true, std::memory_order_release);
        }

        [[nodiscard]] auto PeerRouteSnapshotUnavailable() const noexcept -> bool
        {
            return PeerRouteSnapshotUnavailable_.load(std::memory_order_acquire);
        }
        /** @brief 不可投递的正式失败边界，无新分配、无线程外释放或提前 Leave。 */
        auto BlockDispatch() noexcept -> void
        {
            Barrier.Block();
            DispatchFailed_.store(true);
            if (auto Owner = Storage.lock())
                Owner->Retain(shared_from_this());
        }
        std::shared_ptr<Preview::Executor::ContextOwner> Context;
        std::weak_ptr<Preview::Executor::ClosingStorage> Storage;
        std::atomic<std::shared_ptr<const Prepared>> Value;
        std::atomic<std::shared_ptr<const PeerRouteTable>> PeerRoutes{
            std::make_shared<const PeerRouteTable>()};
        Net::strand<Net::any_io_executor> Strand;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer;
        Preview::Lifecycle::DrainBarrier Barrier;
        std::atomic<bool> Closed{false};
        std::atomic<std::size_t> PendingPackets{0};
        std::unordered_map<std::string, PeerState> Peers;
        std::unordered_map<std::uint64_t, std::shared_ptr<Operation>> Active;
        std::uint64_t NextOperation{0};

    private:
        /** @brief 先 move 保存全部 operation，取消重入不会销毁正在 emit 的 signal；最后完成预约。 */
        auto CloseOnStrand() noexcept -> void
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
        /** @brief 真实 I/O 和 finalizer 全退栈后，在原 executor 释放材料与 DNS 等服务。 */
        auto ReleasePrepared() noexcept -> void
        {
            if (!Finalized_.load() || Barrier.Active() != 0 || Barrier.IsBlocked())
                return;
            Value.store({});
            ResourcesReleased_.store(true);
        }
        /** @brief 最后一个异步准入退栈后，在绑定 strand 评估材料释放。 */
        auto RequestPreparedRelease() noexcept -> void
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
        /** @brief 原 executor 交付动作；隔离时保留同一关闭 owner。 */
        struct PreparedRelease final
        {
            std::shared_ptr<GatewayState> Owner;
            auto operator()() const noexcept -> void { Owner->ReleasePrepared(); }
            auto OnQuarantine() const noexcept -> void { Owner->BlockDispatch(); }
        };
        std::shared_ptr<CloseTicket> Ticket_{std::make_shared<CloseTicket>()};
        std::atomic<bool> Scheduled_{false}, Finalized_{false};
        std::atomic<bool> DispatchFailed_{false}, PeerRouteSnapshotUnavailable_{false};
        std::atomic<bool> ResourcesReleased_{false};
    };

    inline GatewayState::PacketReservation::~PacketReservation() noexcept
    {
        Complete();
    }

    inline auto GatewayState::PacketReservation::Complete() noexcept -> void
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
} // namespace Preview::Shadowsocks2022
