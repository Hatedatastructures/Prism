/** @file Sqlite.hpp @brief 中立 SQLite 所有权、预编译语句及事务；仅由专有存储线程调用。 */
#pragma once
#include <Preview/Foundation/Fault/Failure.hpp>
#include <sqlite3.h>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Storage
{
    /** @brief SQLite 原生错误类别，保留扩展错误码；类别存活到程序结束。 */
    class SqliteCategory final : public std::error_category
    {
    public:
        auto name() const noexcept -> const char* override { return "sqlite"; }
        auto message(int Value) const -> std::string override { return sqlite3_errstr(Value); }
    };
    [[nodiscard]] inline auto SqliteFailure(int Value) -> Fault::Failure
    {
        static const SqliteCategory Category;
        return {Fault::Code::IoError, std::error_code(Value, Category)};
    }
    /** @brief 只穿过同步存储栈，异步边界必须转换回 Failure。 */
    class SqliteError final : public std::runtime_error
    {
    public:
        explicit SqliteError(int Value) : std::runtime_error(sqlite3_errstr(Value)), Code(Value) {}
        int Code;
    };
    /** @brief 不丢精度地编码全部 uint64；数据库中禁止转成 REAL 或有符号 INTEGER。 */
    [[nodiscard]] inline auto Decimal(std::uint64_t Value) -> std::string { return std::to_string(Value); }
    [[nodiscard]] inline auto ParseDecimal(std::string_view Value) -> std::uint64_t
    {
        std::uint64_t Result{};
        const auto Parsed = std::from_chars(Value.data(), Value.data() + Value.size(), Result);
        if (Parsed.ec != std::errc{} || Parsed.ptr != Value.data() + Value.size() || Value.empty())
            throw SqliteError(SQLITE_CORRUPT);
        return Result;
    }
    [[nodiscard]] inline auto AddExact(std::uint64_t Left, std::uint64_t Right) -> std::uint64_t
    {
        if (Right > std::numeric_limits<std::uint64_t>::max() - Left) throw SqliteError(SQLITE_TOOBIG);
        return Left + Right;
    }

    /** @brief 独占 sqlite3_stmt，输入以 SQLITE_TRANSIENT 复制，不保留借用。 */
    class Statement final
    {
    public:
        Statement(sqlite3* Database, std::string_view Sql)
        {
            const auto Code = sqlite3_prepare_v3(Database, Sql.data(), static_cast<int>(Sql.size()), 0, &Value_, nullptr);
            if (Code != SQLITE_OK) throw SqliteError(Code);
        }
        ~Statement() noexcept { if (Value_) sqlite3_finalize(Value_); }
        Statement(const Statement&) = delete;
        auto operator=(const Statement&) -> Statement& = delete;
        Statement(Statement&& Other) noexcept : Value_(std::exchange(Other.Value_, nullptr)) {}
        auto Text(int Index, std::string_view Value) -> void
        {
            Check(sqlite3_bind_text64(Value_, Index, Value.data(), Value.size(), SQLITE_TRANSIENT, SQLITE_UTF8));
        }
        auto Integer(int Index, std::int64_t Value) -> void { Check(sqlite3_bind_int64(Value_, Index, Value)); }
        auto Unsigned(int Index, std::uint64_t Value) -> void { Text(Index, Decimal(Value)); }
        auto Null(int Index) -> void { Check(sqlite3_bind_null(Value_, Index)); }
        [[nodiscard]] auto Step() -> bool
        {
            const auto Code = sqlite3_step(Value_);
            if (Code == SQLITE_ROW) return true;
            if (Code == SQLITE_DONE) return false;
            throw SqliteError(Code);
        }
        auto Run() -> void { if (Step()) throw SqliteError(SQLITE_MISUSE); }
        [[nodiscard]] auto String(int Index) const -> std::string
        {
            const auto* Bytes = sqlite3_column_text(Value_, Index);
            const auto Size = sqlite3_column_bytes(Value_, Index);
            return Bytes ? std::string(reinterpret_cast<const char*>(Bytes), static_cast<std::size_t>(Size)) : std::string{};
        }
        [[nodiscard]] auto Signed(int Index) const -> std::int64_t { return sqlite3_column_int64(Value_, Index); }
        [[nodiscard]] auto Uint(int Index) const -> std::uint64_t { return ParseDecimal(String(Index)); }
        [[nodiscard]] auto IsNull(int Index) const -> bool { return sqlite3_column_type(Value_, Index) == SQLITE_NULL; }
    private:
        static auto Check(int Code) -> void { if (Code != SQLITE_OK) throw SqliteError(Code); }
        sqlite3_stmt* Value_{nullptr};
    };

    /** @brief SQLite 连接只由存储域使用和关闭；析构不取消已提交事务。 */
    class Database final
    {
    public:
        Database() = default;
        Database(const Database&) = delete;
        auto operator=(const Database&) -> Database& = delete;
        ~Database() noexcept { Close(); }
        auto Open(const std::filesystem::path& Path) -> void
        {
            if (Value_) throw SqliteError(SQLITE_MISUSE);
            const auto Encoded = Path.u8string();
            const auto Code = sqlite3_open_v2(reinterpret_cast<const char*>(Encoded.c_str()), &Value_,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr);
            if (Code != SQLITE_OK) { Close(); throw SqliteError(Code); }
            sqlite3_extended_result_codes(Value_, 1);
            sqlite3_busy_timeout(Value_, 5000);
            Execute("PRAGMA foreign_keys=ON");
        }
        auto Close() noexcept -> void
        {
            if (Value_) { sqlite3_close_v2(Value_); Value_ = nullptr; }
        }
        auto Execute(std::string_view Sql) -> void
        {
            const std::string Owned(Sql);
            const auto Code = sqlite3_exec(Value_, Owned.c_str(), nullptr, nullptr, nullptr);
            if (Code != SQLITE_OK) throw SqliteError(Code);
        }
        [[nodiscard]] auto Prepare(std::string_view Sql) -> Statement { return Statement(Value_, Sql); }
        [[nodiscard]] auto Changes() const noexcept -> std::int64_t { return sqlite3_changes64(Value_); }
        [[nodiscard]] auto Scalar(std::string_view Sql) -> std::int64_t
        {
            auto Query = Prepare(Sql);
            if (!Query.Step()) throw SqliteError(SQLITE_CORRUPT);
            return Query.Signed(0);
        }
    private:
        sqlite3* Value_{nullptr};
    };
    /** @brief 事务失败自动回滚；Commit 成功才允许公开任何持久预约。 */
    class Transaction final
    {
    public:
        explicit Transaction(Database& Value) : Database_(Value) { Database_.Execute("BEGIN IMMEDIATE"); }
        ~Transaction() noexcept
        {
            if (!Committed_) try { Database_.Execute("ROLLBACK"); } catch (...) {}
        }
        Transaction(const Transaction&) = delete;
        auto operator=(const Transaction&) -> Transaction& = delete;
        auto Commit() -> void { Database_.Execute("COMMIT"); Committed_ = true; }
    private:
        Database& Database_;
        bool Committed_{false};
    };
}
