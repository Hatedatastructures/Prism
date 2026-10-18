/**
 * @file AccountAdmissionAuthority.hpp
 * @brief 账户局部测试的显式准入 authority，不代替真实 GenerationPublication 覆盖。
 */
#pragma once

#include <Prism/Account/RuntimeRegistry.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Testing
{

    /** @brief 仅覆盖账户账本时使用的按用例撤销表；全应用发布由真实运行时测试负责。 */
    class AccountAdmissionTestAuthority final
        : public Prism::Contract::AccountAdmissionAuthority,
          public Prism::Contract::AccountAdmissionLeaseOwner,
          public std::enable_shared_from_this<AccountAdmissionTestAuthority>
    {
        using Snapshot = Prism::Contract::AccountAdmissionSnapshot;
        using SnapshotPin = Prism::Contract::AccountAdmissionAuthority::SnapshotPin;
        using Result = std::expected<void, Prism::Fault::Failure>;

    public:
        AccountAdmissionTestAuthority()
            : State_(std::make_shared<const Snapshot>(std::vector<Prism::AccountId>{},
                  std::vector<Prism::AccountId>{}, false))
        {
        }

        [[nodiscard]] auto Load() const noexcept -> SnapshotPin override
        {
            return State_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto BeginAdmission(const Prism::AccountId Id) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit,
                Prism::Fault::Failure> override
        {
            if (!Id)
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument});
            }
            if (!TryBeginReader())
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::WouldBlock});
            }
            if (Load()->IsRevoked(Id))
            {
                ReleaseAccountAdmission();
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::Forbidden});
            }
            try
            {
                return Prism::Contract::AccountAdmissionPermit{
                    std::static_pointer_cast<Prism::Contract::AccountAdmissionLeaseOwner>(
                        shared_from_this())};
            }
            catch (...)
            {
                ReleaseAccountAdmission();
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::ResourceUnavailable});
            }
        }

        [[nodiscard]] auto RevokeAccounts(
            const std::span<const Prism::AccountId> Ids) noexcept -> Result override
        {
            if (!TryBeginWriter())
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::WouldBlock});
            }
            auto RevokeResult = RevokeWhileExclusive(Ids);
            EndWriter();
            return RevokeResult;
        }

        /** @brief 账户store局部夹具相互独立；进程关闭行为由真实application用例覆盖。 */
        [[nodiscard]] auto CloseAllAccounts() noexcept -> Result override
        {
            return {};
        }

        auto ReleaseAccountAdmission() noexcept -> void override
        {
            Gate_.fetch_sub(1U, std::memory_order_release);
        }

    private:
        [[nodiscard]] auto TryBeginReader() noexcept -> bool
        {
            auto Current = Gate_.load(std::memory_order_acquire);
            while ((Current & WriterBit) == 0U && Current != WriterBit - 1U)
            {
                if (Gate_.compare_exchange_weak(Current, Current + 1U,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] auto TryBeginWriter() noexcept -> bool
        {
            std::uint64_t Expected = 0U;
            return Gate_.compare_exchange_strong(Expected, WriterBit,
                std::memory_order_acq_rel, std::memory_order_acquire);
        }

        auto EndWriter() noexcept -> void
        {
            Gate_.store(0U, std::memory_order_release);
        }

        [[nodiscard]] auto RevokeWhileExclusive(
            const std::span<const Prism::AccountId> Ids) noexcept -> Result
        {
            try
            {
                const auto Current = State_.load(std::memory_order_acquire);
                auto Revoked = Current->Revoked;
                for (const auto Id : Ids)
                {
                    if (!Id)
                    {
                        return std::unexpected(Prism::Fault::Failure{
                            Prism::Fault::Code::InvalidArgument});
                    }
                    Revoked.push_back(Id);
                }
                std::sort(Revoked.begin(), Revoked.end());
                Revoked.erase(std::unique(Revoked.begin(), Revoked.end()), Revoked.end());
                if (Revoked.size() > Snapshot::MaxRevocations)
                {
                    return std::unexpected(Prism::Fault::Failure{
                        Prism::Fault::Code::ResourceUnavailable});
                }
                State_.store(std::make_shared<const Snapshot>(Current->Members,
                    std::move(Revoked), false), std::memory_order_release);
                return {};
            }
            catch (...)
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::ResourceUnavailable});
            }
        }

        inline static constexpr std::uint64_t WriterBit{std::uint64_t{1U} << 63U};
        std::atomic<std::uint64_t> Gate_{0U};
        std::atomic<std::shared_ptr<const Snapshot>> State_;
    };

    [[nodiscard]] inline auto AccountAdmissionAuthorityForCurrentCase()
        -> std::shared_ptr<AccountAdmissionTestAuthority>
    {
        static const testing::TestInfo *Previous{};
        static std::shared_ptr<AccountAdmissionTestAuthority> Authority;
        const auto *Current = testing::UnitTest::GetInstance()->current_test_info();
        if (!Authority || Current != Previous)
        {
            Authority = std::make_shared<AccountAdmissionTestAuthority>();
            Previous = Current;
        }
        return Authority;
    }

    [[nodiscard]] inline auto AttachAccountAdmissionAuthority(
        const std::shared_ptr<Prism::Account::AccountRuntimeRegistry> &Registry)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Registry)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        return Registry->AttachAdmissionAuthority(AccountAdmissionAuthorityForCurrentCase());
    }

} // namespace Prism::Testing
