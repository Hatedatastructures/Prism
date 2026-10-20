/** @file UsageLedger.hpp @brief 仅存储线程调用的账户预约、累计结算、异常恢复后的人工调整。 */
#pragma once
#include <Prism/Account/UsageModels.hpp>
#include <Prism/Account/UsageCalendar.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Storage/Sqlite.hpp>
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>

namespace Prism::Application::Storage
{
    /** @brief 同步持久适配内核；调用方必须使用 StorageRuntime::Domain，不能在网络线程直接构造。 */
    class UsageLedger final
    {
    public:
        explicit UsageLedger(Prism::Storage::Database& Database) : Database_(Database) {}
        [[nodiscard]] auto ResolveCycle(const Account::UsageCycleRequest& Request)
            -> std::expected<Account::UsageCycle, Fault::Failure>;
        [[nodiscard]] auto Read(const Account::UsageReadRequest& Request)
            -> std::expected<Account::UsageSnapshot, Fault::Failure>;
        [[nodiscard]] auto Reserve(const Account::UsageReservationRequest& Request)
            -> std::expected<Account::UsageReservation, Fault::Failure>;
        [[nodiscard]] auto Settle(const Account::UsageSettlementRequest& Request)
            -> std::expected<Account::UsageSnapshot, Fault::Failure>;
        [[nodiscard]] auto Adjust(const Account::UsageAdjustmentRequest& Request)
            -> std::expected<Account::UsageSnapshot, Fault::Failure>;
    private:
        auto StoreSchedule(std::string_view AccountKey, const Account::UsageSchedule& Value) -> void;
        auto UpdateCycleEnd(std::string_view AccountKey, const Account::UsageCycle& Cycle) -> void;
        static auto Invalid() -> std::unexpected<Fault::Failure>;
        static auto Valid(const Account::UsageReadRequest& Request) -> bool;
        static auto Cycle(const Prism::Storage::Statement& Row, int Column) -> Account::UsageCycle;
        static auto OptionalUint(const Prism::Storage::Statement& Row, int Column)
            -> std::optional<std::uint64_t>;
        static auto BindOptional(Prism::Storage::Statement& Row, int Column,
                                 std::optional<std::uint64_t> Value) -> void;
        static auto BindEnd(Prism::Storage::Statement& Row, int Column,
                            const Account::UsageCycle& Value) -> void;
        static auto Balances(Account::UsageSnapshot& Value) -> void;
        static auto Advance(Account::UsageSnapshot& Snapshot) -> void;
        auto Load(const Account::UsageReadRequest& Request) -> Account::UsageSnapshot;
        auto Store(const Account::UsageSnapshot& Value) -> void;
        auto OutstandingBytes(std::string_view AccountKey) -> std::uint64_t;
        auto ExistingReservation(const Account::UsageReservationRequest& Request)
            -> std::expected<Account::UsageReservation, Fault::Failure>;
        auto InsertReservation(const Account::UsageReservationRequest& Request,
                               const Account::UsageReservation& Value) -> void;
        auto ExistingAdjustment(const Account::UsageAdjustmentRequest& Request)
            -> std::expected<Account::UsageSnapshot, Fault::Failure>;
        auto InsertAdjustment(const Account::UsageAdjustmentRequest& Request,
                              const Account::UsageSnapshot& Value) -> void;
        Prism::Storage::Database& Database_;
    };
}
