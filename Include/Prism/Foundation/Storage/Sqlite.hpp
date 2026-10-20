/** @file Sqlite.hpp @brief 中立 SQLite 所有权、预编译语句及事务；仅由专有存储线程调用。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <sqlite3.h>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace Prism::Storage
{
    /** @brief SQLite 原生错误类别，保留扩展错误码；类别存活到程序结束。 */
    class SqliteCategory final : public std::error_category
    {
    public:
        auto name() const noexcept -> const char* override;
        auto message(int Value) const -> std::string override;
    };
    [[nodiscard]] auto SqliteFailure(int Value) -> Fault::Failure;
    /** @brief 只穿过同步存储栈，异步边界必须转换回 Failure。 */
    class SqliteError final : public std::runtime_error
    {
    public:
        explicit SqliteError(int Value);
        int Code;
    };
    /** @brief 不丢精度地编码全部 uint64；数据库中禁止转成 REAL 或有符号 INTEGER。 */
    [[nodiscard]] auto Decimal(std::uint64_t Value) -> std::string;
    [[nodiscard]] auto ParseDecimal(std::string_view Value) -> std::uint64_t;
    [[nodiscard]] auto AddExact(std::uint64_t Left, std::uint64_t Right) -> std::uint64_t;

    /** @brief 独占 sqlite3_stmt，输入以 SQLITE_TRANSIENT 复制，不保留借用。 */
    class Statement final
    {
    public:
        Statement(sqlite3* Database, std::string_view Sql);
        ~Statement() noexcept;
        Statement(const Statement&) = delete;
        auto operator=(const Statement&) -> Statement& = delete;
        Statement(Statement&& Other) noexcept;
        auto Text(int Index, std::string_view Value) -> void;
        auto Integer(int Index, std::int64_t Value) -> void;
        auto Unsigned(int Index, std::uint64_t Value) -> void;
        auto Null(int Index) -> void;
        [[nodiscard]] auto Step() -> bool;
        auto Run() -> void;
        [[nodiscard]] auto String(int Index) const -> std::string;
        [[nodiscard]] auto Signed(int Index) const -> std::int64_t;
        [[nodiscard]] auto Uint(int Index) const -> std::uint64_t;
        [[nodiscard]] auto IsNull(int Index) const -> bool;
    private:
        static auto Check(int Code) -> void;
        sqlite3_stmt* Value_{nullptr};
    };

    /** @brief SQLite 连接只由存储域使用和关闭；析构不取消已提交事务。 */
    class Database final
    {
    public:
        Database() = default;
        Database(const Database&) = delete;
        auto operator=(const Database&) -> Database& = delete;
        ~Database() noexcept;
        auto Open(const std::filesystem::path& Path) -> void;
        auto Close() noexcept -> void;
        auto Execute(std::string_view Sql) -> void;
        [[nodiscard]] auto Prepare(std::string_view Sql) -> Statement;
        [[nodiscard]] auto Changes() const noexcept -> std::int64_t;
        [[nodiscard]] auto Scalar(std::string_view Sql) -> std::int64_t;
    private:
        sqlite3* Value_{nullptr};
    };
    /** @brief 事务失败自动回滚；Commit 成功才允许公开任何持久预约。 */
    class Transaction final
    {
    public:
        explicit Transaction(Database& Value);
        ~Transaction() noexcept;
        Transaction(const Transaction&) = delete;
        auto operator=(const Transaction&) -> Transaction& = delete;
        auto Commit() -> void;
    private:
        Database& Database_;
        bool Committed_{false};
    };
}
