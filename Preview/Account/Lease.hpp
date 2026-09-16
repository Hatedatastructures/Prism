/**
 * @file Lease.hpp
 * @brief 账户与流租约
 * @details 租约只在原子运行时状态上做一次释放，不持有 I/O 对象；复制被
 *          禁止，移动后源租约为空。
 */
#pragma once

#include "Record.hpp"

#include <cstdint>
#include <memory>
#include <utility>

namespace Preview::Account
{

    class AccountDirectory;

    class StreamLease final
    {
    public:
        StreamLease() = default;

        ~StreamLease()
        {
            Release();
        }

        StreamLease(const StreamLease &) = delete;
        auto operator=(const StreamLease &) -> StreamLease & = delete;

        StreamLease(StreamLease &&Other) noexcept : Runtime_(std::move(Other.Runtime_)), Active_(Other.Active_)
        {
            Other.Active_ = false;
        }

        auto operator=(StreamLease &&Other) noexcept -> StreamLease &
        {
            if (this != &Other)
            {
                Release();
                Runtime_ = std::move(Other.Runtime_);
                Active_ = Other.Active_;
                Other.Active_ = false;
            }
            return *this;
        }

        void Release() noexcept
        {
            if (Active_)
            {
                Active_ = false;
                if (Runtime_)
                {
                    Runtime_->ReleaseStream();
                }
            }
            Runtime_.reset();
        }

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return Active_ && static_cast<bool>(Runtime_);
        }

    private:
        explicit StreamLease(std::shared_ptr<AccountRuntimeState> Runtime)
            : Runtime_(std::move(Runtime)), Active_(static_cast<bool>(Runtime_))
        {
        }

        friend class AccountLease;

        std::shared_ptr<AccountRuntimeState> Runtime_;
        bool Active_{false};
    };

    class AccountLease final
    {
    public:
        AccountLease() = default;

        ~AccountLease()
        {
            Release();
        }

        AccountLease(const AccountLease &) = delete;
        auto operator=(const AccountLease &) -> AccountLease & = delete;

        AccountLease(AccountLease &&Other) noexcept
            : Record_(std::move(Other.Record_)),
              Runtime_(std::move(Other.Runtime_)),
              Policy_(std::move(Other.Policy_)),
              Active_(Other.Active_)
        {
            Other.Active_ = false;
        }

        auto operator=(AccountLease &&Other) noexcept -> AccountLease &
        {
            if (this != &Other)
            {
                Release();
                Record_ = std::move(Other.Record_);
                Runtime_ = std::move(Other.Runtime_);
                Policy_ = std::move(Other.Policy_);
                Active_ = Other.Active_;
                Other.Active_ = false;
            }
            return *this;
        }

        void Release() noexcept
        {
            if (Active_)
            {
                Active_ = false;
                if (Runtime_)
                {
                    Runtime_->ReleaseConnection();
                }
            }
            Runtime_.reset();
            Policy_.reset();
            Record_.reset();
        }

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return Active_ && static_cast<bool>(Runtime_) && static_cast<bool>(Record_) &&
                   static_cast<bool>(Policy_);
        }

        [[nodiscard]] auto Record() const -> SharedAccountRecord
        {
            return Record_;
        }

        [[nodiscard]] auto PolicyGeneration() const noexcept -> Preview::GenerationId
        {
            return Policy_ ? Policy_->Generation() : Preview::GenerationId{};
        }

        [[nodiscard]] auto TryAcquireStream() -> StreamLease
        {
            if (!*this || !Runtime_->TryAcquireStream(Record_->Quota().MaxStreams))
            {
                return {};
            }
            return StreamLease(Runtime_);
        }

        [[nodiscard]] auto TryReserveBytes(const std::uint64_t Amount) noexcept -> bool
        {
            return *this && Policy_->TryReserveBytes(Amount);
        }

        void ReleaseBytes(const std::uint64_t Amount) noexcept
        {
            if (*this)
            {
                Policy_->ReleaseBytes(Amount);
            }
        }

    private:
        struct Binding final
        {
            SharedAccountRecord Record;
            SharedAccountRuntimeState Runtime;
            std::shared_ptr<const AccountRuntimeState::Policy> Policy;
        };

        explicit AccountLease(Binding Value)
            : Record_(std::move(Value.Record)),
              Runtime_(std::move(Value.Runtime)),
              Policy_(std::move(Value.Policy)),
              Active_(true)
        {
        }

        friend class AccountDirectory;

        std::shared_ptr<const AccountRecord> Record_;
        std::shared_ptr<AccountRuntimeState> Runtime_;
        std::shared_ptr<const AccountRuntimeState::Policy> Policy_;
        bool Active_{false};
    };

} // namespace Preview::Account
