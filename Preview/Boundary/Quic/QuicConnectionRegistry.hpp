/**
 * @file QuicConnectionRegistry.hpp
 * @brief Boundary 按 CID 与 peer 管理 QUIC 连接租约。
 * @details 注册表只请求协议连接关闭；UDP socket 的最终关闭者仍是 DatagramListener。
 */
#pragma once

#include <Preview/Boundary/Datagram/DatagramClassifier.hpp>
#include <Preview/Boundary/Quic/QuicAdmissionBudget.hpp>
#include <Preview/Boundary/Quic/QuicConnectionRegistryCloseOwner.hpp>
#include <Preview/Boundary/Quic/QuicConnectionId.hpp>
#include <Preview/Boundary/Quic/QuicInitial.hpp>
#include <Preview/Boundary/Quic/QuicConnectionRegistryDiagnostics.hpp>
#include <Preview/Contract/Ingress/QuicConnection.hpp>
#include <Preview/Contract/Ingress/RequestMetadata.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Identifier/SessionIdAllocator.hpp>
#include <boost/asio/ip/udp.hpp>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Boundary
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    /**
     * @brief Boundary 持有 QUIC CID/peer 表并转交正式连接租约。
     * @details CID 表操作在 listener executor 串行执行。StopAdmission 可跨线程调用，
     *          只原子封止新接入；Drain/Close 需在包处理和 owner 回调静止后执行。
     */
    class QuicConnectionRegistry final
        : public std::enable_shared_from_this<QuicConnectionRegistry>
    {
    public:
        /** @brief 二进制连接标识。 */
        using Cid = Preview::Boundary::QuicConnectionId;

        /** @brief listener 级关闭预算与进程事件观察；factory/代次身份随每包 snapshot 选择。 */
        struct Options final
        {
            QuicConnectionRegistryEventHandler OnEvent;
            /** @brief 与 packet gateway 共享的活动 QUIC owner 预算。 */
            std::shared_ptr<QuicAdmissionBudget> AdmissionBudget;
        };

        /** @brief 将一个 CID alias 绑定到现有协议租约和 peer。 */
        struct Registration final
        {
            Cid ConnectionId;
            std::shared_ptr<Preview::Contract::QuicConnectionLease> Lease;
            Udp::endpoint Peer;
        };

        /**
         * @brief 构造注册表并接收冷路径依赖。
         * @param Value 已绑定的工厂、事件回调和请求元数据。
         */
        explicit QuicConnectionRegistry(Options Value)
            : Options_(std::move(Value)), CloseOwner_(Options_.AdmissionBudget)
        {
            if (!Options_.AdmissionBudget)
            {
                throw std::invalid_argument("QUIC admission budget is required");
            }
        }

        /** @brief 析构时请求关闭仍登记的协议连接。 */
        ~QuicConnectionRegistry()
        {
            (void)Close();
        }

        /**
         * @brief 登记现有租约的 CID alias。
         * @param Input CID、协议租约与 peer；成功时注册表保留共享租约。
         * @return 登记成功返回 true；关闭、冲突或租约无效时返回 false。
         * @note 拒绝时不会将租约转交给表；由输入对象的共享所有权决定其后续寿命。
         */
        [[nodiscard]] auto Register(Registration Input) -> bool
        {
            if (!Input.Lease)
            {
                return false;
            }
            const auto Identity = Input.Lease->Identity();
            const auto State = Input.Lease->State();
            auto Key = std::move(Input.ConnectionId);
            if (Closed_.load(std::memory_order_acquire) ||
                Draining_.load(std::memory_order_acquire) || Key.empty() || !Identity ||
                State.Closed || Entries_.contains(Key))
            {
                return false;
            }

            if (HasOwnerAtDifferentPeer(Identity, Input.Peer))
            {
                return false;
            }

            if (HasPeer(Input.Peer) && !HasPeerOwner(Input.Peer, Identity))
            {
                return false;
            }

            auto Owner = CloseOwner_.Find(Identity);
            const auto NewOwner = !Owner;
            if (NewOwner)
            {
                auto Reservation = CloseOwner_.TryReserve();
                if (!Reservation)
                {
                    return false;
                }
                Owner = CloseOwner_.Retain({Input.Lease, std::move(Reservation), Key});
                if (!Owner)
                {
                    return false;
                }
            }
            else
            {
                CloseOwner_.AddConnectionId(*Owner, Key);
            }

            const auto [It, Inserted] = Entries_.emplace(
                std::move(Key), Entry{Owner, std::move(Input.Peer)});
            (void)It;
            if (!Inserted)
            {
                if (NewOwner)
                {
                    CloseOwner_.Retire(Identity);
                }
                return false;
            }
            if (NewOwner && !Owner->Admission->RetainOwner())
            {
                Entries_.erase(It);
                Owner->Admission->Complete();
                CloseOwner_.Retire(Identity);
                return false;
            }
            return true;
        }

        /**
         * @brief 按 CID、peer 和 QUIC Initial 状态接入一个 Boundary 数据包。
         * @param Packet 完整包视图；方法同步完成分类与协议 ReceivePacket 调用。
         * @param Ingress 当前 packet 单次读取的不可变代次选择；已知 CID 不读取其中新工厂。
         * @return 接受返回 Accepted；满额返回 CapacityExceeded；其他未接入返回 NotHandled。
         * @note 仅未知 CID 分支从 Ingress 单次预约并调用其 factory。
         */
        [[nodiscard]] auto Handle(
            const BoundaryPacket& Packet,
            const std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot>& Ingress)
            -> QuicAdmissionDisposition;

        /**
         * @brief 移除一个 CID alias；最后 alias 移除时请求协议连接关闭。
         * @param ConnectionId 待移除的二进制连接标识。
         * @return 找到并移除登记项返回 true；未找到时返回 false。
         * @note 本方法不关闭 Boundary 拥有的 UDP socket。
         */
        [[nodiscard]] auto Remove(std::span<const std::byte> ConnectionId) -> bool
        {
            const auto It = Entries_.find(ConnectionId);
            if (It == Entries_.end())
            {
                return false;
            }

            auto Owner = It->second.Owner;
            auto Lease = Owner->LeaseValue;
            const auto Identity = Lease->Identity();
            if(Lease->State().Closed)
            {
                const auto Closed = CloseOwner_.RequestClose(*Owner);
                if(!Closed)return false;
                EraseAliases(Identity);
                UpdatePhysicalRetirement();
                return true;
            }
            const auto HasOtherAlias = std::any_of(
                Entries_.begin(), Entries_.end(),
                [It, Identity](const auto& Pair)
                {
                    return Pair.second.Owner->LeaseValue->Identity() == Identity &&
                        std::addressof(Pair.second) != std::addressof(It->second);
                });
            if (HasOtherAlias)
            {
                Entries_.erase(It);
                return true;
            }

            const auto Closed = CloseOwner_.RequestClose(*Owner);
            if (!Closed)
            {
                return false;
            }
            EraseAliases(Identity);
            UpdatePhysicalRetirement();
            return true;
        }

        /** @brief 接受真实 OnClosed 回执并释放唯一 owner 与所有 CID alias。 */
        [[nodiscard]] auto OnOwnerClosed(std::span<const std::byte> ConnectionId) -> bool
        {
            const auto Owner = CloseOwner_.FindByConnectionId(ConnectionId);
            if (!Owner) return false;
            RetireOwner(Owner->Admission.get());
            UpdatePhysicalRetirement();
            return true;
        }

        /** @brief 跨线程封止新 admission；不访问 CID 表或请求连接关闭。 */
        auto StopAdmission() noexcept -> void
        {
            Draining_.store(true, std::memory_order_release);
        }

        /** @brief 请求全部登记 owner 关闭；拒收项保留原 lease 供同 owner 重试。 */
        [[nodiscard]] auto Drain()
            -> std::expected<void, Preview::Fault::Failure>
        {
            StopAdmission();
            return RequestCloseAll();
        }

        /** @brief 请求关闭全部协议租约；拒收项保留原 lease 供同 owner 重试。 */
        [[nodiscard]] auto Close()
            -> std::expected<void, Preview::Fault::Failure>
        {
            StopAdmission();
            Closed_.store(true, std::memory_order_release);
            const auto Result = RequestCloseAll();
            UpdatePhysicalRetirement();
            return Result;
        }

        /** @brief 返回仍有关闭请求被 owner 拒收的 lease。 */
        [[nodiscard]] auto HasPendingClose() const noexcept -> bool
        {
            return CloseOwner_.HasPendingClose();
        }

        /** @brief 只允许对已开始且仍有拒收项的 close stage 做同 owner 重试。 */
        [[nodiscard]] auto CanRetryClose() const noexcept -> bool
        {
            return Closed_.load(std::memory_order_acquire) && CloseOwner_.HasPendingClose();
        }

        /** @brief 返回当前 CID alias 数量。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Entries_.size();
        }

        /** @brief 返回 Gateway 与 Registry 共享预算中的真实活动连接数。 */
        [[nodiscard]] auto ActiveConnectionCount() const noexcept -> std::size_t
        {
            return Options_.AdmissionBudget->ActiveConnections();
        }

        /** @brief listener 已关闭且所有 CID/unique owner 收到真实完成回执时才物理退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        { return PhysicallyRetired_.load(std::memory_order_acquire); }

    private:
        [[nodiscard]] auto HandleUnknownConnection(
            const BoundaryPacket& Packet,
            const std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot>& Ingress)
            -> QuicAdmissionDisposition;

        /** @brief 一个 CID alias 对应的共享协议连接状态。 */
        struct Entry final
        {
            std::shared_ptr<QuicConnectionRegistryCloseOwner::Owner> Owner;
            Udp::endpoint Peer;
        };

        using EntryMap = std::unordered_map<Cid, Entry,
            Preview::Boundary::QuicConnectionIdHash,
            Preview::Boundary::QuicConnectionIdEqual>;
        /**
         * @brief 为协议完成观察创建不会延长注册表寿命的回调。
         * @param ConnectionId 已接入连接的 CID。
         * @return 协议完成后移除 CID alias 的弱观察回调。
         */
        [[nodiscard]] auto CloseObserver(
            const std::shared_ptr<QuicAdmissionBudget::Reservation>& Reservation)
            -> std::function<void()>
        {
            return [Weak = weak_from_this(), Reservation]
            {
                Reservation->Complete();
                if (auto Owner = Weak.lock())
                {
                    Owner->RetireOwner(Reservation.get());
                    Owner->UpdatePhysicalRetirement();
                }
            };
        }

        /**
         * @brief 查找该 peer 下首个仍开放的协议连接 alias。
         * @param Peer 数据包的远端 peer。
         * @return 匹配项迭代器；未找到时为表尾。
         */
        [[nodiscard]] auto FindPeer(const Udp::endpoint& Peer) -> EntryMap::iterator
        {
            return std::find_if(
                Entries_.begin(),
                Entries_.end(),
                [&Peer](const auto& Value)
                {
                    return Value.second.Peer == Peer &&
                        !Value.second.Owner->LeaseValue->State().Closed;
                });
        }

        /**
         * @brief 检查表中是否登记该 peer。
         * @param Peer 要匹配的远端 peer。
         * @return 存在任意 alias 时返回 true。
         */
        [[nodiscard]] auto HasPeer(const Udp::endpoint& Peer) const -> bool
        {
            return std::any_of(
                Entries_.begin(),
                Entries_.end(),
                [&Peer](const auto& Value)
                {
                    return Value.second.Peer == Peer;
                });
        }

        /**
         * @brief 检查 peer 是否由指定 QUIC owner 拥有。
         * @param Peer 要匹配的远端 peer。
         * @param Identity 中立协议 owner 身份。
         * @return 同时匹配 peer 和 owner 时返回 true。
         */
        [[nodiscard]] auto HasPeerOwner(
            const Udp::endpoint& Peer,
            const Preview::Contract::QuicConnectionOwner* Identity) const -> bool
        {
            return std::any_of(
                Entries_.begin(),
                Entries_.end(),
                [&Peer, Identity](const auto& Value)
                {
                    return Value.second.Peer == Peer &&
                        Value.second.Owner->LeaseValue->Identity() == Identity;
                });
        }

        /**
         * @brief 检查 QUIC owner 是否已绑定到另一个 peer。
         * @param Identity 中立协议 owner 身份。
         * @param Peer 当前登记的远端 peer。
         * @return 同一 owner 已绑定其他 peer 时返回 true。
         */
        [[nodiscard]] auto HasOwnerAtDifferentPeer(
            const Preview::Contract::QuicConnectionOwner* Identity,
            const Udp::endpoint& Peer) const -> bool
        {
            return std::any_of(
                Entries_.begin(),
                Entries_.end(),
                [&Peer, Identity](const auto& Value)
                {
                    return Value.second.Peer != Peer &&
                        Value.second.Owner->LeaseValue->Identity() == Identity;
                });
        }

        /** @brief 关闭命令接受后移除路由 alias；unique owner 留待真实完成回执。 */
        auto EraseAliases(const Preview::Contract::QuicConnectionOwner* Identity) -> void
        {
            for (auto It = Entries_.begin(); It != Entries_.end();)
            {
                if (It->second.Owner->LeaseValue->Identity() == Identity)
                {
                    It = Entries_.erase(It);
                }
                else
                {
                    ++It;
                }
            }
        }

        /** @brief 在真实协议完成回执后释放唯一 owner reservation 与全部 alias。 */
        auto RetireOwner(const QuicAdmissionBudget::Reservation* Reservation) -> void
        {
            const auto Owner = CloseOwner_.Find(Reservation);
            if (!Owner)
            {
                return;
            }
            Owner->Admission->Complete();
            const auto Identity = Owner->LeaseValue->Identity();
            EraseAliases(Identity);
            CloseOwner_.Retire(Identity);
        }

        /** @brief 对唯一 owner 发起 close，并清除已接受命令的路由 alias。 */
        [[nodiscard]] auto RequestCloseAll()
            -> std::expected<void, Preview::Fault::Failure>
        {
            const auto Result = CloseOwner_.RequestCloseAll();
            for (auto It = Entries_.begin(); It != Entries_.end();)
            {
                if (It->second.Owner->CloseAccepted)
                {
                    It = Entries_.erase(It);
                }
                else
                {
                    ++It;
                }
            }
            return Result;
        }

        /**
         * @brief 将数据包交给中立协议 owner 并处理关闭与预算结果。
         * @param It 命中的注册表项。
         * @param Packet 完整 Boundary 数据包。
         * @return 已接纳、应交给其他入口处理或拒绝该包。
         */
        [[nodiscard]] auto DispatchAndPrune(
            EntryMap::iterator It,
            const BoundaryPacket& Packet) -> QuicAdmissionDisposition
        {
            auto Owner = It->second.Owner;
            auto Lease = Owner->LeaseValue;
            const auto Identity = Lease->Identity();
            const auto Before = Lease->State();
            const auto PeerMatches = It->second.Peer == Packet.Peer;

            if (!PeerMatches)
            {
                Notify(QuicConnectionRegistryStage::ReceiveRejected, false);
                return QuicAdmissionDisposition::NotHandled;
            }

            if (Before.Closed)
            {
                Notify(QuicConnectionRegistryStage::ReceiveRejected, false);
                if (Lease->State().Closed)
                {
                    const auto Closed = CloseOwner_.RequestClose(*Owner);
                    if (Closed)
                    {
                        EraseAliases(Identity);
                    }
                }
                return QuicAdmissionDisposition::Rejected;
            }

            if (!Owner->Admission->CanAcceptPacket())
            {
                Notify(QuicConnectionRegistryStage::ReceiveRejected, false);
                if (Lease->State().Closed)
                {
                    const auto Closed = CloseOwner_.RequestClose(*Owner);
                    if (Closed)
                    {
                        EraseAliases(Identity);
                    }
                }
                return QuicAdmissionDisposition::NotHandled;
            }

            const auto Accepted = Lease->ReceivePacket(Packet.Payload, Packet.Peer);
            if (Accepted)
            {
                Owner->Admission->RecordAcceptedPacket();
                Notify(QuicConnectionRegistryStage::ReceiveAccepted, true);
            }
            else
            {
                Notify(QuicConnectionRegistryStage::ReceiveRejected, false);
            }

            if (Lease->State().Closed)
            {
                const auto Closed = CloseOwner_.RequestClose(*Owner);
                if (Closed)
                {
                    EraseAliases(Identity);
                }
            }

            if (Accepted)
            {
                return QuicAdmissionDisposition::Accepted;
            }
            return QuicAdmissionDisposition::Rejected;
        }

        /** @brief 发送诊断事件；诊断回调异常不会改变数据面结果。 */
        auto Notify(QuicConnectionRegistryStage Stage, bool Accepted) noexcept -> void
        {
            NotifyQuicConnectionRegistryEvent(
                Options_.OnEvent, {Stage, Accepted, ActiveConnectionCount()});
        }

        /** @brief 在 CID executor 记录所有 owner completion 后的线程安全物理退休回执。 */
        auto UpdatePhysicalRetirement() noexcept -> void
        {
            if (Closed_.load(std::memory_order_acquire) && Entries_.empty() &&
                CloseOwner_.Size() == 0U)
            {
                PhysicallyRetired_.store(true, std::memory_order_release);
            }
        }


        Options Options_;
        QuicConnectionRegistryCloseOwner CloseOwner_;
        EntryMap Entries_;
        std::atomic<bool> Draining_{false};
        std::atomic<bool> Closed_{false};
        std::atomic<bool> PhysicallyRetired_{false};
    };
}

#include <Preview/Boundary/Quic/QuicConnectionRegistryAdmission.hpp>
