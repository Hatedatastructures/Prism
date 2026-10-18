/**
 * @file SessionRegistryAccountRetirement.hpp
 * @brief AccountRuntime 下会话的拒绝准入、取消与真实退栈协调。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/SessionControl.hpp>
#include <Prism/Runtime/SessionRegistryModel.hpp>
#include <Prism/Runtime/SessionRegistryRetirement.hpp>
#include <Prism/Runtime/SessionRegistryStorage.hpp>

namespace Prism::Runtime::Detail
{

    /** @brief 拥有 AccountRuntime 退休顺序，确保先封止注册，再取消并等待 owner 退栈。 */
    class SessionRegistryAccountRetirement final
    {
    public:
        [[nodiscard]] static auto CancelAndDrain(
            std::shared_ptr<SessionRegistryState> State,
            const Prism::AccountId Account,
            const Prism::Account::AccountRuntimeIdentity Runtime)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            if (!Account || !Runtime.IsValid())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            const auto Denied = SessionRegistryStorage::DenyAccountRuntime(
                State, Account.Value(), Runtime);
            if (!Denied)
            {
                co_return std::unexpected(Denied.error());
            }

            const auto Current = State->Records.load(std::memory_order_seq_cst);
            struct PendingOwner final
            {
                std::shared_ptr<SessionRegistryEntry> Entry;
                std::shared_ptr<SessionControl> Control;
            };
            std::vector<PendingOwner> Owners;
            std::optional<Prism::Fault::Failure> FirstFailure;
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                if (RecordValue.Info.AccountId != Account ||
                    RecordValue.Info.AccountRuntime != Runtime)
                {
                    continue;
                }
                auto Control = SessionRegistryStorage::GetActiveControl(RecordValue.Entry);
                if (!Control && !RecordValue.Entry->Removed.load(std::memory_order_acquire))
                {
                    if (!FirstFailure)
                    {
                        FirstFailure = Prism::Fault::Failure{
                            Prism::Fault::Code::Blocked};
                    }
                    continue;
                }
                Owners.push_back(PendingOwner{RecordValue.Entry, std::move(Control)});
            }

            for (const auto &Owner : Owners)
            {
                if (!Owner.Control)
                {
                    continue;
                }
                const auto Cancelled = Owner.Control->Cancel();
                if (!Cancelled && !FirstFailure)
                {
                    FirstFailure = Cancelled.error();
                }
            }
            for (const auto &Owner : Owners)
            {
                if (!Owner.Control)
                {
                    continue;
                }
                const auto Drained = co_await Owner.Control->Drain();
                if (!Drained && !FirstFailure)
                {
                    FirstFailure = Drained.error();
                }
            }
            if (FirstFailure)
            {
                co_return std::unexpected(*FirstFailure);
            }
            for (const auto &Owner : Owners)
            {
                const auto Retired = co_await SessionRegistryRetirement::AwaitRetirement(Owner.Entry);
                if (!Retired && !FirstFailure)
                {
                    FirstFailure = Retired.error();
                }
            }
            if (FirstFailure)
            {
                co_return std::unexpected(*FirstFailure);
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] static auto ReleaseGate(
            const std::shared_ptr<SessionRegistryState> &State,
            const Prism::AccountId Account,
            const Prism::Account::AccountRuntimeIdentity Runtime)
            -> std::expected<void, Prism::Fault::Failure>
        {
            return SessionRegistryStorage::RemoveAccountRuntimeDenial(
                State, Account.Value(), Runtime);
        }
    };

} // namespace Prism::Runtime::Detail
