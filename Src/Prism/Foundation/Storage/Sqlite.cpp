/** @file Sqlite.cpp
 * @brief SQLite 错误映射、语句、数据库连接与事务实现。
 */
#include <Prism/Foundation/Storage/Sqlite.hpp>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace Prism::Storage
{
    auto SqliteCategory::name() const noexcept -> const char*
    {
        return "sqlite";
    }

    auto SqliteCategory::message(const int Value) const -> std::string
    {
        return sqlite3_errstr(Value);
    }

    auto SqliteFailure(const int Value) -> Fault::Failure
    {
        static const SqliteCategory Category;
        return {Fault::Code::IoError, std::error_code(Value, Category)};
    }

    SqliteError::SqliteError(const int Value)
        : std::runtime_error(sqlite3_errstr(Value)), Code(Value)
    {
    }

    auto Decimal(const std::uint64_t Value) -> std::string
    {
        return std::to_string(Value);
    }

    auto ParseDecimal(const std::string_view Value) -> std::uint64_t
    {
        std::uint64_t Result{};
        const auto Parsed = std::from_chars(Value.data(), Value.data() + Value.size(), Result);
        if (Parsed.ec != std::errc{} || Parsed.ptr != Value.data() + Value.size() || Value.empty())
            throw SqliteError(SQLITE_CORRUPT);
        return Result;
    }

    auto AddExact(const std::uint64_t Left, const std::uint64_t Right) -> std::uint64_t
    {
        if (Right > std::numeric_limits<std::uint64_t>::max() - Left) throw SqliteError(SQLITE_TOOBIG);
        return Left + Right;
    }

    Statement::Statement(sqlite3* Database, const std::string_view Sql)
    {
        const auto Code = sqlite3_prepare_v3(Database, Sql.data(), static_cast<int>(Sql.size()), 0, &Value_, nullptr);
        if (Code != SQLITE_OK) throw SqliteError(Code);
    }

    Statement::~Statement() noexcept
    {
        if (Value_) sqlite3_finalize(Value_);
    }

    Statement::Statement(Statement&& Other) noexcept : Value_(std::exchange(Other.Value_, nullptr))
    {
    }

    auto Statement::Text(const int Index, const std::string_view Value) -> void
    {
        Check(sqlite3_bind_text64(Value_, Index, Value.data(), Value.size(), SQLITE_TRANSIENT, SQLITE_UTF8));
    }

    auto Statement::Integer(const int Index, const std::int64_t Value) -> void
    {
        Check(sqlite3_bind_int64(Value_, Index, Value));
    }

    auto Statement::Unsigned(const int Index, const std::uint64_t Value) -> void
    {
        Text(Index, Decimal(Value));
    }

    auto Statement::Null(const int Index) -> void
    {
        Check(sqlite3_bind_null(Value_, Index));
    }

    auto Statement::Step() -> bool
    {
        const auto Code = sqlite3_step(Value_);
        if (Code == SQLITE_ROW) return true;
        if (Code == SQLITE_DONE) return false;
        throw SqliteError(Code);
    }

    auto Statement::Run() -> void
    {
        if (Step()) throw SqliteError(SQLITE_MISUSE);
    }

    auto Statement::String(const int Index) const -> std::string
    {
        const auto* Bytes = sqlite3_column_text(Value_, Index);
        const auto Size = sqlite3_column_bytes(Value_, Index);
        return Bytes ? std::string(reinterpret_cast<const char*>(Bytes), static_cast<std::size_t>(Size)) : std::string{};
    }

    auto Statement::Signed(const int Index) const -> std::int64_t
    {
        return sqlite3_column_int64(Value_, Index);
    }

    auto Statement::Uint(const int Index) const -> std::uint64_t
    {
        return ParseDecimal(String(Index));
    }

    auto Statement::IsNull(const int Index) const -> bool
    {
        return sqlite3_column_type(Value_, Index) == SQLITE_NULL;
    }

    auto Statement::Check(const int Code) -> void
    {
        if (Code != SQLITE_OK) throw SqliteError(Code);
    }

    Database::~Database() noexcept
    {
        Close();
    }

    auto Database::Open(const std::filesystem::path& Path) -> void
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

    auto Database::Close() noexcept -> void
    {
        if (Value_) { sqlite3_close_v2(Value_); Value_ = nullptr; }
    }

    auto Database::Execute(const std::string_view Sql) -> void
    {
        const std::string Owned(Sql);
        const auto Code = sqlite3_exec(Value_, Owned.c_str(), nullptr, nullptr, nullptr);
        if (Code != SQLITE_OK) throw SqliteError(Code);
    }

    auto Database::Prepare(const std::string_view Sql) -> Statement
    {
        return Statement(Value_, Sql);
    }

    auto Database::Changes() const noexcept -> std::int64_t
    {
        return sqlite3_changes64(Value_);
    }

    auto Database::Scalar(const std::string_view Sql) -> std::int64_t
    {
        auto Query = Prepare(Sql);
        if (!Query.Step()) throw SqliteError(SQLITE_CORRUPT);
        return Query.Signed(0);
    }

    Transaction::Transaction(Database& Value) : Database_(Value)
    {
        Database_.Execute("BEGIN IMMEDIATE");
    }

    Transaction::~Transaction() noexcept
    {
        if (!Committed_) try { Database_.Execute("ROLLBACK"); } catch (...) {}
    }

    auto Transaction::Commit() -> void
    {
        Database_.Execute("COMMIT");
        Committed_ = true;
    }
}
