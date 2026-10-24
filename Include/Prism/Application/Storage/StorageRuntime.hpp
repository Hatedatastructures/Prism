/** @file StorageRuntime.hpp @brief 两库、实例身份、单写目录与异步关闭的进程级所有者。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Storage/Sqlite.hpp>
#include <Prism/Resource/Storage/Executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <tuple>

namespace Prism::Application::Storage::Detail
{
    class DirectoryLock;
}

namespace Prism::Application::Storage
{
    struct StorageOptions final
    {
        std::filesystem::path Directory;
        std::string Incarnation;
        std::uint64_t HistoryBudgetBytes{4ULL * 1024ULL * 1024ULL * 1024ULL};
    };
    /**
     * @brief Application 持有到所有协议、统计和操作 owner 排空，再等待 Shutdown。
     * @details 打开、迁移、事务及关闭均在专属存储线程。数据库引用仅允许 Execute 工作中借用。
     *          InstanceKey 持久，Incarnation 每进程唯一；不得用运行时账户数字 ID 做持久主键。
     */
    class StorageRuntime final : public std::enable_shared_from_this<StorageRuntime>
    {
    public:
        explicit StorageRuntime(StorageOptions Options);
        ~StorageRuntime();
        [[nodiscard]] static auto Open(StorageOptions Options)
            -> boost::asio::awaitable<std::expected<std::shared_ptr<StorageRuntime>, Fault::Failure>>;
        [[nodiscard]] auto Domain() const -> std::shared_ptr<Resource::Storage::Executor> { return Domain_; }
        [[nodiscard]] auto InstanceKey() const -> const std::string& { return InstanceKey_; }
        [[nodiscard]] auto Incarnation() const -> const std::string& { return Incarnation_; }
        [[nodiscard]] auto Options() const -> const StorageOptions& { return Options_; }
        /** @brief 只能在本 owner 的存储执行域同步工作中借用。 */
        [[nodiscard]] auto Ledger() -> Prism::Storage::Database& { return Ledger_; }
        [[nodiscard]] auto History() -> Prism::Storage::Database& { return History_; }
        [[nodiscard]] auto Shutdown() -> boost::asio::awaitable<std::expected<void, Fault::Failure>>;
        /** @brief 完成 Shutdown 后由进程冷关闭路径等待专属线程真实退出。 */
        auto Join() -> void;
    private:
        static auto RandomKey(Prism::Storage::Database& Database) -> std::string;
        auto Initialize() -> void;
        static auto CheckVersion(Prism::Storage::Database& Database) -> void;
        auto InitializeLedger() -> void;
        /** @brief 遗留预约转异常占额；已 checkpoint 的消耗保持已结算，不重复扣量。 */
        auto RecoverReservations() -> void;
        auto RecoverReservation(
            const std::tuple<std::string, std::string, std::int64_t, std::uint64_t>& Row) -> void;
        auto InitializeHistory() -> void;
        StorageOptions Options_;
        std::shared_ptr<Resource::Storage::Executor> Domain_;
        std::unique_ptr<Detail::DirectoryLock> Lock_;
        Prism::Storage::Database Ledger_;
        Prism::Storage::Database History_;
        std::string InstanceKey_;
        std::string Incarnation_;
    };
}
