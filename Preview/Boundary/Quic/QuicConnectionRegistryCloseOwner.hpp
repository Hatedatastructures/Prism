/**
 * @file QuicConnectionRegistryCloseOwner.hpp
 * @brief Registry unique owner、close receipt 与 admission reservation 的 owner。
 * @details CID alias 可删除或重绑；本 owner 独立保留 lease 与预算，直到完成观察或
 *          显式外部移除确认真实退休。
 */
#pragma once

#include <Preview/Boundary/Quic/QuicAdmissionBudget.hpp>
#include <Preview/Boundary/Quic/QuicConnectionId.hpp>
#include <Preview/Contract/Ingress/QuicConnection.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>

#include <algorithm>
#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Boundary
{

    /** @brief 只按唯一协议 owner 身份计数和重试 QUIC close。 */
    class QuicConnectionRegistryCloseOwner final
    {
    public:
        using Lease = Preview::Contract::QuicConnectionLease;
        using OwnerIdentity = const Preview::Contract::QuicConnectionOwner*;
        using Reservation = QuicAdmissionBudget::Reservation;

        /** @brief 一条 QUIC lease 的 owner 级资源和关闭回执。 */
        struct Owner final
        {
            std::shared_ptr<Lease> LeaseValue;
            std::shared_ptr<Reservation> Admission;
            std::vector<QuicConnectionId> ConnectionIds;
            std::optional<Preview::Fault::Failure> CloseFailure;
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
            std::shared_ptr<QuicAdmissionBudget> Budget)
            : Budget_(std::move(Budget))
        {
        }

        /** @brief 为新连接预留全局容量；超限时不创建 owner。 */
        [[nodiscard]] auto TryReserve() -> std::shared_ptr<Reservation>
        {
            return Budget_->TryReserve();
        }

        /** @brief 按稳定身份查找已保留 owner。 */
        [[nodiscard]] auto Find(const OwnerIdentity Identity) const noexcept
            -> std::shared_ptr<Owner>
        {
            const auto It = Owners_.find(Identity);
            return It == Owners_.end() ? std::shared_ptr<Owner>{} : It->second;
        }

        /** @brief 按 completion reservation 查找 owner。 */
        [[nodiscard]] auto Find(const Reservation* Value) const noexcept
            -> std::shared_ptr<Owner>
        {
            const auto It = std::find_if(Owners_.begin(), Owners_.end(),
                [Value](const auto& Pair)
                {
                    return Pair.second->Admission.get() == Value;
                });
            return It == Owners_.end() ? std::shared_ptr<Owner>{} : It->second;
        }

        /** @brief 为新 owner 建立唯一 slot。 */
        [[nodiscard]] auto Retain(Admission Input) -> std::shared_ptr<Owner>
        {
            if (!Input.LeaseValue || !Input.ReservationValue ||
                !Input.LeaseValue->Identity())
            {
                return {};
            }
            auto Value = std::make_shared<Owner>(Owner{
                std::move(Input.LeaseValue), std::move(Input.ReservationValue),
                {std::move(Input.ConnectionId)}, {}, false});
            const auto Identity = Value->LeaseValue->Identity();
            const auto [It, Inserted] = Owners_.emplace(Identity, Value);
            return Inserted ? Value : It->second;
        }

        /** @brief 将另一个 CID alias 计入同一 unique owner。 */
        auto AddConnectionId(Owner& Value, QuicConnectionId ConnectionId) -> void
        {
            if (std::find(Value.ConnectionIds.begin(), Value.ConnectionIds.end(), ConnectionId) ==
                Value.ConnectionIds.end())
            {
                Value.ConnectionIds.push_back(std::move(ConnectionId));
            }
        }

        /** @brief 查找外部注册 lease 所保留的 CID owner。 */
        [[nodiscard]] auto FindByConnectionId(
            const std::span<const std::byte> ConnectionId) const -> std::shared_ptr<Owner>
        {
            for (const auto& Pair : Owners_)
            {
                const auto Match = std::find_if(Pair.second->ConnectionIds.begin(),
                    Pair.second->ConnectionIds.end(),
                    [ConnectionId](const QuicConnectionId& Candidate)
                    {
                        return Candidate.size() == ConnectionId.size() &&
                            std::equal(Candidate.begin(), Candidate.end(), ConnectionId.begin());
                    });
                if (Match != Pair.second->ConnectionIds.end())
                {
                    return Pair.second;
                }
            }
            return {};
        }

        /** @brief 只在真实 completion observer 或外部退休确认后释放 owner 槽。 */
        auto Retire(const OwnerIdentity Identity) -> void
        {
            Owners_.erase(Identity);
        }

        /** @brief 请求一次关闭并保留首次未接受原因。 */
        [[nodiscard]] auto RequestClose(Owner& Value)
            -> std::expected<void, Preview::Fault::Failure>
        {
            const auto Result = Value.LeaseValue->RequestClose();
            if (Result)
            {
                Value.CloseFailure.reset();
                Value.CloseAccepted = true;
                return {};
            }
            if (!Value.CloseFailure)
            {
                Value.CloseFailure = Result.error();
            }
            Value.CloseAccepted = false;
            return std::unexpected(*Value.CloseFailure);
        }

        /** @brief 继续请求所有唯一 owner，保留各自失败与 reservation。 */
        [[nodiscard]] auto RequestCloseAll()
            -> std::expected<void, Preview::Fault::Failure>
        {
            const auto Snapshot = Owners_;
            auto FirstFailure = std::optional<Preview::Fault::Failure>{};
            for (const auto& Pair : Snapshot)
            {
                const auto Result = RequestClose(*Pair.second);
                if (!Result && !FirstFailure)
                {
                    FirstFailure = Result.error();
                }
            }
            if (FirstFailure)
            {
                return std::unexpected(*FirstFailure);
            }
            return {};
        }

        /** @brief 返回是否仍有可重试的 typed close failure。 */
        [[nodiscard]] auto HasPendingClose() const noexcept -> bool
        {
            return std::any_of(Owners_.begin(), Owners_.end(),
                [](const auto& Pair)
                {
                    return Pair.second->CloseFailure.has_value();
                });
        }

        /** @brief 返回仍保留容量的 unique owner 数。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Owners_.size();
        }

    private:
        std::shared_ptr<QuicAdmissionBudget> Budget_;
        std::unordered_map<OwnerIdentity, std::shared_ptr<Owner>> Owners_;
    };

} // namespace Preview::Boundary
