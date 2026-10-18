/** @file SqliteTest.cpp @brief 中立数据库精确整数、事务回滚和错误保真。 */
#include <Prism/Foundation/Storage/Sqlite.hpp>
#include <gtest/gtest.h>
#include <limits>

namespace
{
    TEST(StorageSqlite, PreservesUnsignedMaximum)
    {
        Prism::Storage::Database Database;
        Database.Open(":memory:");
        Database.Execute("CREATE TABLE counter(value TEXT NOT NULL)");
        auto Insert = Database.Prepare("INSERT INTO counter VALUES(?)");
        Insert.Unsigned(1, std::numeric_limits<std::uint64_t>::max());
        Insert.Run();
        auto Read = Database.Prepare("SELECT value FROM counter");
        ASSERT_TRUE(Read.Step());
        EXPECT_EQ(Read.Uint(0), std::numeric_limits<std::uint64_t>::max());
    }
    TEST(StorageSqlite, RollsBackUncommittedTransaction)
    {
        Prism::Storage::Database Database;
        Database.Open(":memory:");
        Database.Execute("CREATE TABLE value(item INTEGER)");
        {
            Prism::Storage::Transaction Transaction(Database);
            Database.Execute("INSERT INTO value VALUES(7)");
        }
        EXPECT_EQ(Database.Scalar("SELECT COUNT(*) FROM value"), 0);
    }
    TEST(StorageSqlite, RejectsMalformedOrOverflowingUnsignedText)
    {
        EXPECT_THROW(Prism::Storage::ParseDecimal("18446744073709551616"), Prism::Storage::SqliteError);
        EXPECT_THROW(Prism::Storage::ParseDecimal("-1"), Prism::Storage::SqliteError);
        EXPECT_THROW(Prism::Storage::ParseDecimal("7x"), Prism::Storage::SqliteError);
        EXPECT_THROW(Prism::Storage::AddExact(std::numeric_limits<std::uint64_t>::max(), 1),
            Prism::Storage::SqliteError);
    }
}
