/** @file SqliteTest.cpp @brief 中立数据库精确整数、事务回滚和错误保真。 */
#include <Preview/Foundation/Storage/Sqlite.hpp>
#include <gtest/gtest.h>
#include <limits>

namespace
{
    TEST(StorageSqlite, PreservesUnsignedMaximum)
    {
        Preview::Storage::Database Database;
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
        Preview::Storage::Database Database;
        Database.Open(":memory:");
        Database.Execute("CREATE TABLE value(item INTEGER)");
        {
            Preview::Storage::Transaction Transaction(Database);
            Database.Execute("INSERT INTO value VALUES(7)");
        }
        EXPECT_EQ(Database.Scalar("SELECT COUNT(*) FROM value"), 0);
    }
    TEST(StorageSqlite, RejectsMalformedOrOverflowingUnsignedText)
    {
        EXPECT_THROW(Preview::Storage::ParseDecimal("18446744073709551616"), Preview::Storage::SqliteError);
        EXPECT_THROW(Preview::Storage::ParseDecimal("-1"), Preview::Storage::SqliteError);
        EXPECT_THROW(Preview::Storage::ParseDecimal("7x"), Preview::Storage::SqliteError);
        EXPECT_THROW(Preview::Storage::AddExact(std::numeric_limits<std::uint64_t>::max(), 1),
            Preview::Storage::SqliteError);
    }
}
