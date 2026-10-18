/**
 * @file CandidateHandle.hpp
 * @brief 持有不可变候选 owner 的识别句柄
 * @details 句柄按 CandidateId 重新解析，跨协程时不暴露候选 vector 的裸地址。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <Prism/Runtime/Recognition/Candidate.hpp>

namespace Prism::Recognition
{

    class Profile;

    /**
     * @class CandidateHandle
     * @brief 持有候选 owner 的访问句柄
     * @details 每次访问按 ID 查找，避免跨协程保存 CandidateSpec 引用或指针。
     */
    class CandidateHandle
    {
    public:
        CandidateHandle() = default;

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Resolve() != nullptr;
        }

        [[nodiscard]] auto Id() const noexcept -> CandidateId
        {
            return Id_;
        }

        [[nodiscard]] auto Name() const -> std::string
        {
            const auto *Candidate = Resolve();
            return Candidate ? Candidate->Name : std::string{};
        }

        [[nodiscard]] auto Scheme() const -> std::string
        {
            const auto *Candidate = Resolve();
            return Candidate ? Candidate->Scheme : std::string{};
        }

        [[nodiscard]] auto Protocol() const noexcept -> Prism::Contract::ProtocolType
        {
            const auto *Candidate = Resolve();
            return Candidate ? Candidate->Protocol : Prism::Contract::ProtocolType::Unknown;
        }

        [[nodiscard]] auto Kind() const noexcept -> CandidateKind
        {
            const auto *Candidate = Resolve();
            return Candidate ? Candidate->Kind : CandidateKind::Cleartext;
        }

        [[nodiscard]] auto Priority() const noexcept -> std::uint16_t
        {
            const auto *Candidate = Resolve();
            return Candidate ? Candidate->Priority : 0;
        }

        [[nodiscard]] auto Tier() const noexcept -> std::uint8_t
        {
            const auto *Candidate = Resolve();
            return Candidate ? Candidate->Tier : 0;
        }

        [[nodiscard]] auto MinimumBytes() const noexcept -> std::size_t
        {
            const auto *Candidate = Resolve();
            return Candidate ? Candidate->MinimumBytes : 0;
        }

        [[nodiscard]] auto Inspect(const ProbeSnapshot &Snapshot) const -> MatchState
        {
            const auto *Candidate = Resolve();
            if (!Candidate || !Candidate->Inspect)
            {
                return MatchState::Rejected;
            }
            return Candidate->Inspect(Snapshot);
        }

        [[nodiscard]] auto HasPrepare() const noexcept -> bool
        {
            const auto *Candidate = Resolve();
            return Candidate && static_cast<bool>(Candidate->Prepare);
        }

        /** @brief 查询冻结候选的认证要求；句柄持有 owner，失效句柄返回 false，无 I/O 或取消。 */
        [[nodiscard]] auto RequiresAuthentication() const noexcept -> bool
        {
            const auto *Candidate = Resolve();
            return Candidate && Candidate->RequiresAuthentication;
        }

        [[nodiscard]] auto HasCommit() const noexcept -> bool
        {
            const auto *Candidate = Resolve();
            return Candidate && static_cast<bool>(Candidate->Commit);
        }

        [[nodiscard]] auto Prepare(PrepareContext Context) const -> Net::awaitable<PrepareResult>
        {
            return PrepareOwned(Owner_, Id_, std::move(Context));
        }

        [[nodiscard]] auto Commit(CommitContext Context) const -> Net::awaitable<CommitResult>
        {
            return CommitOwned(Owner_, Id_, std::move(Context));
        }

    private:
        friend class Profile;

        CandidateHandle(SharedCandidateStore Owner, CandidateId Id)
            : Owner_(std::move(Owner)), Id_(Id)
        {
        }

        [[nodiscard]] static auto PrepareOwned(SharedCandidateStore Owner, CandidateId Id,
                                                PrepareContext Context)
            -> Net::awaitable<PrepareResult>
        {
            const CandidateSpec *Candidate = Owner ? Owner->Find(Id) : nullptr;
            if (!Candidate || !Candidate->Prepare)
            {
                PrepareResult Result;
                Result.Candidate = Id;
                co_return Result;
            }
            Context.Candidate = Id;
            co_return co_await Candidate->Prepare(std::move(Context));
        }

        [[nodiscard]] static auto CommitOwned(SharedCandidateStore Owner, CandidateId Id,
                                               CommitContext Context)
            -> Net::awaitable<CommitResult>
        {
            const CandidateSpec *Candidate = Owner ? Owner->Find(Id) : nullptr;
            if (!Candidate || !Candidate->Commit)
            {
                CommitResult Result;
                Result.Candidate = Id;
                co_return Result;
            }
            Context.Candidate = Id;
            co_return co_await Candidate->Commit(std::move(Context));
        }

        [[nodiscard]] auto Resolve() const noexcept -> const CandidateSpec *
        {
            return Owner_ ? Owner_->Find(Id_) : nullptr;
        }

        SharedCandidateStore Owner_;
        CandidateId Id_{InvalidCandidate};
    };

} // namespace Prism::Recognition
