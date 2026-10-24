/**
 * @file GenerationPublication.hpp
 * @brief 以单次原子交换发布 generation 与账户准入权威状态。
 */
#pragma once

#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Runtime
{

    /** @brief 一次原子 publication 读取到的代次 owner 与账户 admission 事实。 */
    struct GenerationPublicationView final
    {
        Prism::Foundation::GenerationPin Active;
        Prism::Contract::AccountAdmissionAuthority::SnapshotPin Accounts;
    };

    /** @brief 单一运行时发布器；generation 与账户准入事实属于同一个原子状态。 */
    class GenerationPublication final
        : public Prism::Contract::AccountAdmissionAuthority
    {
        using AccountSnapshot = Prism::Contract::AccountAdmissionSnapshot;
        using AccountSnapshotPin = Prism::Contract::AccountAdmissionAuthority::SnapshotPin;
        using Failure = Prism::Fault::Failure;

        struct Retired final
        {
            Prism::GenerationId Id{};
            std::weak_ptr<const Prism::Foundation::GenerationLifetime> Owner;
        };

        struct Published final
        {
            std::shared_ptr<const Prism::Foundation::GenerationLifetime> Active;
            std::vector<Retired> RetiredGenerations;
            AccountSnapshotPin Accounts;
        };

    public:
        inline static constexpr std::size_t MaxRetainedGenerations{8U};

        /** @brief 可提交 token 固定唯一 expected state 与唯一 next state。 */
        class PrepareToken final
        {
            friend class GenerationPublication;

            PrepareToken(std::shared_ptr<const Published> ExpectedValue,
                         std::shared_ptr<const Published> NextValue) noexcept
                : Expected_(std::move(ExpectedValue)), Next_(std::move(NextValue))
            {
            }

            std::shared_ptr<const Published> Expected_;
            std::shared_ptr<const Published> Next_;
        };

        enum class PrepareError : std::uint8_t
        {
            MissingGeneration,
            StaleBase,
            NonMonotonicGeneration,
            RetentionLimit,
            InvalidAccount,
            AccountLimit,
            RevocationLimit,
            Closed,
        };

        enum class PublishError : std::uint8_t
        {
            AdmissionBusy,
            StaleBase,
            InvalidToken,
        };

        GenerationPublication();

        [[nodiscard]] auto Current() const noexcept
            -> std::shared_ptr<const Prism::Foundation::GenerationLifetime>;

        /** @brief 同一次原子加载返回当前完整代次 owner 和对应账户准入视图。 */
        [[nodiscard]] auto Read() const noexcept -> GenerationPublicationView;

        [[nodiscard]] auto Contains(const Prism::GenerationId Id) const noexcept -> bool;

        [[nodiscard]] auto RetainedCount() const noexcept -> std::size_t;

        /** @brief 账户模块单次读取与 generation 同一发布记录中的不可变准入快照。 */
        [[nodiscard]] auto Load() const noexcept -> AccountSnapshotPin override;

        /** @brief 在同一 CAS 前后以读 gate 固定账户准入线性区。 */
        [[nodiscard]] auto BeginAdmission(const Prism::AccountId Id) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit, Failure> override;

        /** @brief 撤销墓碑经唯一发布 CAS 可见，不触碰账户 runtime 的第二撤销位。 */
        [[nodiscard]] auto RevokeAccounts(
            const std::span<const Prism::AccountId> Ids) noexcept
            -> std::expected<void, Failure> override;

        /** @brief process shutdown 将全账户封止状态并入同一不可变 publication。 */
        [[nodiscard]] auto CloseAllAccounts() noexcept
            -> std::expected<void, Failure> override;

        /** @brief 验证候选成员、墓碑预算和 generation 顺序，不改变 live state。 */
        [[nodiscard]] auto Prepare(
            const std::shared_ptr<const Prism::Foundation::GenerationLifetime> &Expected,
            std::shared_ptr<const Prism::Foundation::GenerationLifetime> Candidate,
            std::vector<Prism::AccountId> CandidateAccounts) const
            -> std::expected<PrepareToken, PrepareError>;

        /** @brief 唯一 CAS 同时发布 generation、成员集和已保留撤销墓碑。 */
        [[nodiscard]] auto Publish(PrepareToken &Token) noexcept
            -> std::expected<void, PublishError>;

        /** @brief shutdown 已排空活动 owner 后原子关闭准入并清除 generation pin。 */
        [[nodiscard]] auto Clear() noexcept -> bool;

    private:
        [[nodiscard]] static auto PrepareAccounts(
            const AccountSnapshot &Current,
            std::vector<Prism::AccountId> Members)
            -> std::expected<AccountSnapshotPin, PrepareError>;

        [[nodiscard]] auto RevokeWhileExclusive(
            const std::span<const Prism::AccountId> Ids) noexcept
            -> std::expected<void, Failure>;

        [[nodiscard]] auto CloseAccountsWhileExclusive() noexcept
            -> std::expected<void, Failure>;

        const std::shared_ptr<Prism::Contract::AccountAdmissionGate> AdmissionGate_;
        std::atomic<std::shared_ptr<const Published>> State_;
    };

} // namespace Prism::Runtime
