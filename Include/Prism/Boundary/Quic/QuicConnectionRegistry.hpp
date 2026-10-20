/**
 * @file QuicConnectionRegistry.hpp
 * @brief Boundary 按 CID 与 peer 管理 QUIC 连接租约。
 * @details 注册表只请求协议连接关闭；UDP socket 的最终关闭者仍是 DatagramListener。
 */
#pragma once

#include <Prism/Boundary/Datagram/DatagramClassifier.hpp>
#include <Prism/Boundary/Quic/QuicAdmissionBudget.hpp>
#include <Prism/Boundary/Quic/QuicConnectionRegistryTypes.hpp>
#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/ip/udp.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>

namespace Prism::Boundary
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
        using Cid = Prism::Boundary::QuicConnectionId;

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
            std::shared_ptr<Prism::Contract::QuicConnectionLease> Lease;
            Udp::endpoint Peer;
        };

        /**
         * @brief 构造注册表并接收冷路径依赖。
         * @param Value 已绑定的工厂、事件回调和请求元数据。
         */
        explicit QuicConnectionRegistry(Options Value);

        /** @brief 析构时请求关闭仍登记的协议连接。 */
        ~QuicConnectionRegistry();

        /**
         * @brief 登记现有租约的 CID alias。
         * @param Input CID、协议租约与 peer；成功时注册表保留共享租约。
         * @return 登记成功返回 true；关闭、冲突或租约无效时返回 false。
         * @note 拒绝时不会将租约转交给表；由输入对象的共享所有权决定其后续寿命。
         */
        [[nodiscard]] auto Register(Registration Input) -> bool;

        /**
         * @brief 按 CID、peer 和 QUIC Initial 状态接入一个 Boundary 数据包。
         * @param Packet 完整包视图；方法同步完成分类与协议 ReceivePacket 调用。
         * @param Ingress 当前 packet 单次读取的不可变代次选择；已知 CID 不读取其中新工厂。
         * @return 接受返回 Accepted；满额返回 CapacityExceeded；其他未接入返回 NotHandled。
         * @note 仅未知 CID 分支从 Ingress 单次预约并调用其 factory。
         */
        [[nodiscard]] auto Handle(
            const BoundaryPacket& Packet,
            const std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot>& Ingress)
            -> QuicAdmissionDisposition;

        /**
         * @brief 移除一个 CID alias；最后 alias 移除时请求协议连接关闭。
         * @param ConnectionId 待移除的二进制连接标识。
         * @return 找到并移除登记项返回 true；未找到时返回 false。
         * @note 本方法不关闭 Boundary 拥有的 UDP socket。
         */
        [[nodiscard]] auto Remove(std::span<const std::byte> ConnectionId) -> bool;

        /** @brief 接受真实 OnClosed 回执并释放唯一 owner 与所有 CID alias。 */
        [[nodiscard]] auto OnOwnerClosed(std::span<const std::byte> ConnectionId) -> bool;

        /** @brief 跨线程封止新 admission；不访问 CID 表或请求连接关闭。 */
        auto StopAdmission() noexcept -> void;

        /** @brief 请求全部登记 owner 关闭；拒收项保留原 lease 供同 owner 重试。 */
        [[nodiscard]] auto Drain() -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 请求关闭全部协议租约；拒收项保留原 lease 供同 owner 重试。 */
        [[nodiscard]] auto Close() -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 返回仍有关闭请求被 owner 拒收的 lease。 */
        [[nodiscard]] auto HasPendingClose() const noexcept -> bool;

        /** @brief 只允许对已开始且仍有拒收项的 close stage 做同 owner 重试。 */
        [[nodiscard]] auto CanRetryClose() const noexcept -> bool;

        /** @brief 返回当前 CID alias 数量。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t;

        /** @brief 返回 Gateway 与 Registry 共享预算中的真实活动连接数。 */
        [[nodiscard]] auto ActiveConnectionCount() const noexcept -> std::size_t;

        /** @brief listener 已关闭且所有 CID/unique owner 收到真实完成回执时才物理退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

    private:
        struct State;
        std::unique_ptr<State> State_;
    };
}
