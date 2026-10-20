/** @file GatewayState.hpp @brief raw UDP 实物、实际 I/O 屏障及原 executor 关闭所有者。 */
#pragma once
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Shadowsocks2022/Prepared.hpp>

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
#include <chrono>
#include <string>
namespace Prism::Shadowsocks2022
{
    /** @brief 接入前构造的关闭槽位；不引用 binding/gateway，L1 只保存本实物。 */
    class GatewayState final : public Prism::Executor::ClosingResource,
                               public std::enable_shared_from_this<GatewayState>
    {
        struct CloseTicket final
        {
            std::optional<Prism::Lifecycle::DrainReservation> Reservation;
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
            PacketBudget(PacketBudget &&Other) noexcept;
            auto operator=(PacketBudget &&Other) noexcept -> PacketBudget & = delete;
            ~PacketBudget() noexcept;
            /** @brief 在 packet 退栈时先归还预算，再评估 owner 是否可释放。 */
            auto Release() noexcept -> void;
        private:
            friend class GatewayState;
            explicit PacketBudget(std::atomic<std::size_t> *Pending);
            std::atomic<std::size_t> *Pending_{nullptr};
        };

        /** @brief 持有 raw datagram 的活动预约、包预算及真实 GatewayState owner。 */
        class PacketReservation final
        {
        public:
            PacketReservation(const PacketReservation &) = delete;
            auto operator=(const PacketReservation &) -> PacketReservation & = delete;
            PacketReservation(PacketReservation &&Other) noexcept;
            auto operator=(PacketReservation &&Other) noexcept -> PacketReservation & = delete;
            ~PacketReservation() noexcept;

        private:
            friend class GatewayState;
            PacketReservation(std::shared_ptr<GatewayState> Owner,
                Prism::Lifecycle::DrainReservation Activity,
                PacketBudget Budget);
            auto Complete() noexcept -> void;

            std::shared_ptr<GatewayState> Owner_;
            Prism::Lifecycle::DrainReservation Activity_;
            PacketBudget Budget_;
            bool Completed_{true};
        };

        /** @brief 一次 raw UDP 入队/运行资格，统一持有真实 DrainBarrier 与包预算预留。 */
        class PacketAdmission final
        {
        public:
            PacketAdmission(const PacketAdmission &) = delete;
            auto operator=(const PacketAdmission &) -> PacketAdmission & = delete;
            PacketAdmission(PacketAdmission &&Other) noexcept;
            auto operator=(PacketAdmission &&Other) noexcept -> PacketAdmission & = delete;
            [[nodiscard]] auto Packet() const noexcept
                -> const Prism::Contract::DatagramPacket &
            {
                return Packet_;
            }

        private:
            friend class GatewayState;
            friend class Ss2022Gateway;
            [[nodiscard]] auto TakeGenerationUseLease() noexcept
                -> Prism::Foundation::GenerationUseLease
            {
                return std::move(Packet_.GenerationUse);
            }
            PacketAdmission(Prism::Contract::DatagramPacket Packet,
                PacketReservation Reservation);

            PacketReservation Reservation_;
            Prism::Contract::DatagramPacket Packet_;
        };

        struct PeerRoute final
        {
            boost::asio::ip::udp::endpoint Peer;
            std::uintptr_t CredentialBinding{0};
            std::uintptr_t CredentialMaterial{0};
            Prism::AccountId Account;
            Prism::GenerationId Generation;
            std::array<std::uint8_t, SessionIdLen> ClientSession{};
            bool HasAccountLease{false};
            bool HasGenerationUse{false};
        };

        using PeerRouteTable = std::vector<PeerRoute>;

        struct PeerState final
        {
            Prism::Protocols::ScopedMaterial Credential;
            Prism::Account::AccountLease Lease;
            Prism::Foundation::GenerationUseLease GenerationUse;
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
        explicit GatewayState(std::shared_ptr<const Prepared> PreparedValue);
        /** @brief 任意线程先预约 finalizer 再封止；关闭与 peer lease 释放只能在原 strand。 */
        auto Close() noexcept -> void;
        /** @brief 最后 gateway owner 释放时保存尚未执行的 finalizer，反向联系不保留 gateway。 */
        auto OwnerReleased() noexcept -> void;
        /** @brief 沿唯一 reclaimer 请求回收；不可投递时保留同一个预构造实物到 L1。 */
        auto RequestRetirement() noexcept -> void override;
        /** @brief 关闭 finalizer 和所有真实 I/O 预约均完成才退休；Closed 标记不能代替此事实。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override;
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;

        /** @brief 以真实活动预约和有界包预算取得一次 owning packet 准入资格。 */
        [[nodiscard]] auto PreparePacketAdmission(
            Prism::Contract::DatagramPacket Packet) -> std::optional<PacketAdmission>;

    private:
        /** @brief 仅由准入票据申请；成功后由同一票据持有直到真实退栈。 */
        [[nodiscard]] auto ReservePacket() noexcept -> std::optional<PacketBudget>;

    public:

        /** @brief 在 gateway strand 发布带 peer/account/generation lease 回执的只读快照。 */
        auto PublishPeerRoutes() noexcept -> bool;
        /** @brief 在修改 strand peer map 前封止过期快照读，提交新快照后重新开放。 */
        auto BeginPeerRouteMutation() noexcept -> void;

        [[nodiscard]] auto PeerRouteSnapshotUnavailable() const noexcept -> bool;
        /** @brief 不可投递的正式失败边界，无新分配、无线程外释放或提前 Leave。 */
        auto BlockDispatch() noexcept -> void;
        std::shared_ptr<Prism::Executor::ContextOwner> Context;
        std::weak_ptr<Prism::Executor::ClosingStorage> Storage;
        std::atomic<std::shared_ptr<const Prepared>> Value;
        std::atomic<std::shared_ptr<const PeerRouteTable>> PeerRoutes{
            std::make_shared<const PeerRouteTable>()};
        Net::strand<Net::any_io_executor> Strand;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
        Prism::Lifecycle::DrainBarrier Barrier;
        std::atomic<bool> Closed{false};
        std::atomic<std::size_t> PendingPackets{0};
        std::unordered_map<std::string, PeerState> Peers;
        std::unordered_map<std::uint64_t, std::shared_ptr<Operation>> Active;
        std::uint64_t NextOperation{0};

    private:
        /** @brief 先 move 保存全部 operation，取消重入不会销毁正在 emit 的 signal；最后完成预约。 */
        auto CloseOnStrand() noexcept -> void;
        /** @brief 真实 I/O 和 finalizer 全退栈后，在原 executor 释放材料与 DNS 等服务。 */
        auto ReleasePrepared() noexcept -> void;
        /** @brief 最后一个异步准入退栈后，在绑定 strand 评估材料释放。 */
        auto RequestPreparedRelease() noexcept -> void;
        /** @brief 原 executor 交付动作；隔离时保留同一关闭 owner。 */
        struct PreparedRelease final
        {
            std::shared_ptr<GatewayState> Owner;
            auto operator()() const noexcept -> void;
            auto OnQuarantine() const noexcept -> void;
        };
        std::shared_ptr<CloseTicket> Ticket_{std::make_shared<CloseTicket>()};
        std::atomic<bool> Scheduled_{false}, Finalized_{false};
        std::atomic<bool> DispatchFailed_{false}, PeerRouteSnapshotUnavailable_{false};
        std::atomic<bool> ResourcesReleased_{false};
    };




} // namespace Prism::Shadowsocks2022
