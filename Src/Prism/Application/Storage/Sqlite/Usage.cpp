/** @file Usage.cpp @brief 将账户持久请求调度到 SQLite owner 执行域。 */

#include <Prism/Application/Storage/Sqlite/Detail/Usage.hpp>
#include <Prism/Application/Storage/StorageRuntime.hpp>
#include <Prism/Application/Storage/UsageLedger.hpp>

#include <stdexcept>
#include <utility>

namespace Prism::Application::Storage
{

    SqliteUsagePersistence::SqliteUsagePersistence(std::shared_ptr<StorageRuntime> Owner)
        : Owner_(std::move(Owner))
    {
        if (!Owner_)
        {
            throw std::invalid_argument("storage owner required");
        }
    }

    auto SqliteUsagePersistence::ResolveCycle(Account::UsageCycleRequest Request)
        -> boost::asio::awaitable<std::expected<Account::UsageCycle, Fault::Failure>>
    {
        const auto Owner = Owner_;
        co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]
        {
            return UsageLedger(Owner->Ledger()).ResolveCycle(Request);
        });
    }

    auto SqliteUsagePersistence::Read(Account::UsageReadRequest Request)
        -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>>
    {
        const auto Owner = Owner_;
        co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]
        {
            return UsageLedger(Owner->Ledger()).Read(Request);
        });
    }

    auto SqliteUsagePersistence::Reserve(Account::UsageReservationRequest Request)
        -> boost::asio::awaitable<std::expected<Account::UsageReservation, Fault::Failure>>
    {
        const auto Owner = Owner_;
        co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]
        {
            return UsageLedger(Owner->Ledger()).Reserve(Request);
        });
    }

    auto SqliteUsagePersistence::Settle(Account::UsageSettlementRequest Request)
        -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>>
    {
        const auto Owner = Owner_;
        co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]
        {
            return UsageLedger(Owner->Ledger()).Settle(Request);
        });
    }

    auto SqliteUsagePersistence::Adjust(Account::UsageAdjustmentRequest Request)
        -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>>
    {
        const auto Owner = Owner_;
        co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]
        {
            return UsageLedger(Owner->Ledger()).Adjust(Request);
        });
    }

} // namespace Prism::Application::Storage
