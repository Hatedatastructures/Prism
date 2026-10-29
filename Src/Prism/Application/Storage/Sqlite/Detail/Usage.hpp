/** @file Usage.hpp @brief 专属 SQLite 执行域的账户持久端口适配接口。 */
#pragma once

#include <Prism/Account/UsagePersistence.hpp>

#include <memory>

namespace Prism::Application::Storage
{

    class StorageRuntime;

    /** @brief 持有 storage 句柄；Application 关闭该共享数据库 owner。 */
    class SqliteUsagePersistence final : public Account::UsagePersistence
    {
    public:
        explicit SqliteUsagePersistence(std::shared_ptr<StorageRuntime> Owner);

        auto ResolveCycle(Account::UsageCycleRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageCycle, Fault::Failure>> override;
        auto Read(Account::UsageReadRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>> override;
        auto Reserve(Account::UsageReservationRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageReservation, Fault::Failure>> override;
        auto Settle(Account::UsageSettlementRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>> override;
        auto Adjust(Account::UsageAdjustmentRequest Request)
            -> boost::asio::awaitable<std::expected<Account::UsageSnapshot, Fault::Failure>> override;

    private:
        std::shared_ptr<StorageRuntime> Owner_;
    };

} // namespace Prism::Application::Storage
