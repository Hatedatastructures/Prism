/**
 * @file QuicConnectionRegistryCloseOwner.hpp
 * @brief QUIC Registry 唯一协议 owner、reservation 与 close receipt 私有存储。
 */
#pragma once

#include <Prism/Boundary/Quic/QuicAdmissionBudget.hpp>
#include <Prism/Boundary/Quic/QuicConnectionRegistryTypes.hpp>
#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace Prism::Boundary
{
    /** @brief 只按唯一协议 owner 身份计数和重试 QUIC close。 */
    class QuicConnectionRegistryCloseOwner final
    {
    public:
        using Lease = Prism::Contract::QuicConnectionLease;
        using OwnerIdentity = const Prism::Contract::QuicConnectionOwner*;
        using Reservation = QuicAdmissionBudget::Reservation;

        /** @brief 一条 QUIC lease 的 owner 级资源和关闭回执。 */
        struct Owner final
        {
            std::shared_ptr<Lease> LeaseValue;
            std::shared_ptr<Reservation> Admission;
            std::vector<QuicConnectionId> ConnectionIds;
            std::optional<Prism::Fault::Failure> CloseFailure;
            bool CloseAccepted{false};
        };

        /** @brief 接管新 unique owner 与它的首个 CID。 */
        struct Admission final
        {
            std::shared_ptr<Lease> LeaseValue;
            std::shared_ptr<Reservation> ReservationValue;
            QuicConnectionId ConnectionId;
        };

        explicit QuicConnectionRegistryCloseOwner(
            std::shared_ptr<QuicAdmissionBudget> Budget);

        /** @brief 为新连接预留全局容量；超限时不创建 owner。 */
        [[nodiscard]] auto TryReserve() -> std::shared_ptr<Reservation>;

        /** @brief 按稳定身份查找已保留 owner。 */
        [[nodiscard]] auto Find(const OwnerIdentity Identity) const noexcept
            -> std::shared_ptr<Owner>;

        /** @brief 按 completion reservation 查找 owner。 */
        [[nodiscard]] auto Find(const Reservation* Value) const noexcept
            -> std::shared_ptr<Owner>;

        /** @brief 为新 owner 建立唯一 slot。 */
        [[nodiscard]] auto Retain(Admission Input) -> std::shared_ptr<Owner>;

        /** @brief 将另一个 CID alias 计入同一 unique owner。 */
        auto AddConnectionId(Owner& Value, QuicConnectionId ConnectionId) -> void;

        /** @brief 查找外部注册 lease 所保留的 CID owner。 */
        [[nodiscard]] auto FindByConnectionId(
            std::span<const std::byte> ConnectionId) const -> std::shared_ptr<Owner>;

        /** @brief 只在真实 completion observer 或外部退休确认后释放 owner 槽。 */
        auto Retire(OwnerIdentity Identity) -> void;

        /** @brief 请求一次关闭并保留首次未接受原因。 */
        [[nodiscard]] auto RequestClose(Owner& Value)
            -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 继续请求所有唯一 owner，保留各自失败与 reservation。 */
        [[nodiscard]] auto RequestCloseAll()
            -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 返回是否仍有可重试的 typed close failure。 */
        [[nodiscard]] auto HasPendingClose() const noexcept -> bool;

        /** @brief 返回仍保留容量的 unique owner 数。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t;

    private:
        std::shared_ptr<QuicAdmissionBudget> Budget_;
        std::unordered_map<OwnerIdentity, std::shared_ptr<Owner>> Owners_;
    };
}
