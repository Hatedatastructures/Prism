/** @file SqliteUsagePersistence.hpp @brief Account 异步持久端口到专属 SQLite 执行域的正式适配。 */
#pragma once
#include <Prism/Account/UsagePersistence.hpp>
#include <Prism/Application/Storage/UsageLedger.hpp>
#include <memory>

namespace Prism::Application::Storage
{
    /** @brief 拥有 storage 句柄；Application 排空使用者后统一关闭 storage，不在此关闭数据库。 */
    class SqliteUsagePersistence final : public Account::UsagePersistence
    {
    public:
        explicit SqliteUsagePersistence(std::shared_ptr<StorageRuntime> Owner) : Owner_(std::move(Owner))
        { if (!Owner_) throw std::invalid_argument("storage owner required"); }
        auto ResolveCycle(Account::UsageCycleRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageCycle, Fault::Failure>> override
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return UsageLedger(Owner->Ledger()).ResolveCycle(Request); });
        }
        auto Read(Account::UsageReadRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>> override
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return UsageLedger(Owner->Ledger()).Read(Request); });
        }
        auto Reserve(Account::UsageReservationRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageReservation, Fault::Failure>> override
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return UsageLedger(Owner->Ledger()).Reserve(Request); });
        }
        auto Settle(Account::UsageSettlementRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>> override
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return UsageLedger(Owner->Ledger()).Settle(Request); });
        }
        auto Adjust(Account::UsageAdjustmentRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>> override
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return UsageLedger(Owner->Ledger()).Adjust(Request); });
        }
    private:
        std::shared_ptr<StorageRuntime> Owner_;
    };
}
