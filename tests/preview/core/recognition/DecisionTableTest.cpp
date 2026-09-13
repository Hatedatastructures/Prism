/**
 * @file DecisionTableTest.cpp
 * @brief 固定候选位图与首字节索引测试
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>

#include <preview/Runtime/Recognition/DecisionTable.hpp>
#include <preview/Runtime/Recognition/Types.hpp>

namespace
{

    namespace rec = Preview::Recognition;

    // 捕获生产错误：固定位图越界或交集实现错误会污染候选集合。
    TEST(DecisionTableTest, SupportsFixed128BitRangeAndIntersection)
    {
        rec::CandidateBitmap Left;
        rec::CandidateBitmap Right;
        EXPECT_TRUE(Left.Set(0));
        EXPECT_TRUE(Left.Set(63));
        EXPECT_TRUE(Left.Set(127));
        EXPECT_FALSE(Left.Set(128));
        EXPECT_TRUE(Right.Set(63));
        EXPECT_TRUE(Right.Set(127));

        Left.Intersect(Right);
        EXPECT_FALSE(Left.Test(0));
        EXPECT_TRUE(Left.Test(63));
        EXPECT_TRUE(Left.Test(127));
        EXPECT_FALSE(Left.Test(128));
        EXPECT_EQ(Left.Count(), 2U);
    }

    // 捕获生产错误：首字节桶和 fallback 合并错误会漏识别候选协议。
    TEST(DecisionTableTest, Uses256FirstByteEntriesAndFallbackBitmap)
    {
        rec::DecisionTable Table;
        ASSERT_TRUE(Table.AddFirstByte(0x05, 1));
        ASSERT_TRUE(Table.AddFallback(7));

        const std::array<std::byte, 1> Socks5{static_cast<std::byte>(0x05)};
        const auto SocksResult = Table.Lookup(Socks5);
        EXPECT_EQ(SocksResult.State, rec::MatchState::Structural);
        EXPECT_TRUE(SocksResult.Candidates.Test(1));
        EXPECT_TRUE(SocksResult.Candidates.Test(7));

        const std::array<std::byte, 1> Opaque{static_cast<std::byte>(0xAA)};
        const auto OpaqueResult = Table.Lookup(Opaque);
        EXPECT_EQ(OpaqueResult.State, rec::MatchState::Structural);
        EXPECT_FALSE(OpaqueResult.Candidates.Test(1));
        EXPECT_TRUE(OpaqueResult.Candidates.Test(7));

        EXPECT_TRUE(Table.Lookup(static_cast<std::uint8_t>(0x05)).Test(1));
        EXPECT_TRUE(Table.Lookup(static_cast<std::uint8_t>(0xFF)).Test(7));
    }

    // 捕获生产错误：首字节索引容量不足会覆盖或丢失 256 个桶中的候选。
    TEST(DecisionTableTest, RetainsAll256FirstByteBuckets)
    {
        rec::DecisionTable Table;
        for (std::size_t Value = 0; Value < rec::DecisionTable::FirstByteCount; ++Value)
        {
            const auto Id = static_cast<rec::CandidateId>(Value % rec::CandidateBitmap::Capacity);
            EXPECT_TRUE(Table.AddFirstByte(static_cast<std::uint8_t>(Value), Id));
            EXPECT_TRUE(Table.Lookup(static_cast<std::uint8_t>(Value)).Test(Id));
        }
    }

    // 捕获生产错误：最小字节边界判断错误会过早解析或重复读取。
    TEST(DecisionTableTest, ReportsNeedMoreAtCandidateMinimumBoundary)
    {
        rec::DecisionTable Table;
        ASSERT_TRUE(Table.AddFirstByte(0x16, 9));
        ASSERT_TRUE(Table.SetMinimumBytes(9, 2));

        const std::array<std::byte, 1> Prefix{static_cast<std::byte>(0x16)};
        const auto Pending = Table.Lookup(Prefix);
        EXPECT_EQ(Pending.State, rec::MatchState::NeedMore);
        EXPECT_EQ(Pending.RequiredBytes, 2U);
        EXPECT_FALSE(Pending.Deterministic);

        const std::array<std::byte, 2> Complete{
            static_cast<std::byte>(0x16), static_cast<std::byte>(0x03)};
        const auto Ready = Table.Lookup(Complete);
        EXPECT_EQ(Ready.State, rec::MatchState::Structural);
        EXPECT_EQ(Ready.RequiredBytes, 2U);
        EXPECT_TRUE(Ready.Deterministic);
    }

    // 捕获生产错误：越界 CandidateId 若写入位图会发生移位越界或候选污染。
    TEST(DecisionTableTest, RejectsOutOfRangeCandidateIds)
    {
        rec::DecisionTable Table;
        EXPECT_FALSE(Table.AddFirstByte(0x00, 128));
        EXPECT_FALSE(Table.AddFallback(128));
        EXPECT_FALSE(Table.SetMinimumBytes(128, 2));
        EXPECT_EQ(Table.Lookup(static_cast<std::uint8_t>(0x00)).Count(), 0U);
    }

    // 捕获生产错误：没有任何候选时若继续等待会让识别流程无谓阻塞。
    TEST(DecisionTableTest, RejectsWhenNoIndexedOrFallbackCandidateExists)
    {
        rec::DecisionTable Table;
        const std::array<std::byte, 1> Data{static_cast<std::byte>(0x01)};
        const auto Result = Table.Lookup(Data);
        EXPECT_EQ(Result.State, rec::MatchState::Rejected);
        EXPECT_TRUE(Result.Candidates.Empty());
        EXPECT_EQ(Result.RequiredBytes, 1U);
        EXPECT_FALSE(Result.Deterministic);
    }

    // 捕获生产错误：多个候选的预读边界不能只取第一个候选的最小值。
    TEST(DecisionTableTest, UsesMaximumMinimumAcrossIndexedCandidates)
    {
        rec::DecisionTable Table;
        ASSERT_TRUE(Table.AddFirstByte(0x21, 3));
        ASSERT_TRUE(Table.AddFirstByte(0x21, 4));
        ASSERT_TRUE(Table.SetMinimumBytes(3, 4));
        ASSERT_TRUE(Table.SetMinimumBytes(4, 7));

        const std::array<std::byte, 6> Prefix{
            static_cast<std::byte>(0x21), static_cast<std::byte>(0x01), static_cast<std::byte>(0x02),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0x04), static_cast<std::byte>(0x05)};
        const auto Pending = Table.Lookup(Prefix);
        EXPECT_EQ(Pending.State, rec::MatchState::NeedMore);
        EXPECT_EQ(Pending.Candidates.Count(), 2U);
        EXPECT_EQ(Pending.RequiredBytes, 7U);

        const std::array<std::byte, 7> Complete{
            static_cast<std::byte>(0x21), static_cast<std::byte>(0x01), static_cast<std::byte>(0x02),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0x04), static_cast<std::byte>(0x05),
            static_cast<std::byte>(0x06)};
        const auto Ready = Table.Lookup(Complete);
        EXPECT_EQ(Ready.State, rec::MatchState::Structural);
        EXPECT_EQ(Ready.RequiredBytes, 7U);
        EXPECT_FALSE(Ready.Deterministic);
    }

    // 捕获生产错误：空输入命中 fallback 时必须报告 fallback 候选的最大预读边界。
    TEST(DecisionTableTest, UsesFallbackMinimumForEmptyInput)
    {
        rec::DecisionTable Table;
        ASSERT_TRUE(Table.AddFallback(5));
        ASSERT_TRUE(Table.AddFallback(6));
        ASSERT_TRUE(Table.SetMinimumBytes(5, 3));
        ASSERT_TRUE(Table.SetMinimumBytes(6, 9));

        const auto Result = Table.Lookup(std::span<const std::byte>{});
        EXPECT_EQ(Result.State, rec::MatchState::NeedMore);
        EXPECT_TRUE(Result.Candidates.Test(5));
        EXPECT_TRUE(Result.Candidates.Test(6));
        EXPECT_EQ(Result.RequiredBytes, 9U);
        EXPECT_FALSE(Result.Deterministic);
    }

    // 捕获生产错误：空输入且全表无候选时继续等待会让识别流程无谓阻塞。
    TEST(DecisionTableTest, RejectsEmptyInputWithoutFallbackCandidates)
    {
        rec::DecisionTable Table;
        const auto Result = Table.Lookup(std::span<const std::byte>{});
        EXPECT_EQ(Result.State, rec::MatchState::Rejected);
        EXPECT_TRUE(Result.Candidates.Empty());
        EXPECT_EQ(Result.RequiredBytes, 1U);
        EXPECT_FALSE(Result.Deterministic);
    }

    // 捕获生产错误：空输入的 indexed-only 候选必须等待首字节并报告最早可用边界。
    TEST(DecisionTableTest, WaitsForIndexedCandidatesWithEmptyInput)
    {
        rec::DecisionTable Table;
        ASSERT_TRUE(Table.AddFirstByte(0x52, 14));
        ASSERT_TRUE(Table.AddFirstByte(0xA7, 15));
        ASSERT_TRUE(Table.SetMinimumBytes(14, 5));
        ASSERT_TRUE(Table.SetMinimumBytes(15, 3));

        const auto Result = Table.Lookup(std::span<const std::byte>{});
        EXPECT_EQ(Result.State, rec::MatchState::NeedMore);
        EXPECT_TRUE(Result.Candidates.Test(14));
        EXPECT_TRUE(Result.Candidates.Test(15));
        EXPECT_EQ(Result.RequiredBytes, 3U);
        EXPECT_FALSE(Result.Deterministic);
    }

    // 捕获生产错误：发布后的决策表不能通过默认赋值替换内容或复位 sealed 状态。
    TEST(DecisionTableTest, AssignmentCannotReplacePublishedTable)
    {
        static_assert(std::is_copy_constructible_v<rec::DecisionTable>);
        static_assert(std::is_move_constructible_v<rec::DecisionTable>);
        static_assert(!std::is_copy_assignable_v<rec::DecisionTable>);
        static_assert(!std::is_move_assignable_v<rec::DecisionTable>);

        rec::DecisionTable Table;
        ASSERT_TRUE(Table.AddFirstByte(0x63, 8));
        ASSERT_TRUE(Table.SetMinimumBytes(8, 6));
        ASSERT_TRUE(Table.Seal());

        const rec::DecisionTable Copy(Table);
        EXPECT_TRUE(Copy.IsSealed());
        EXPECT_TRUE(Copy.CandidatesFor(0x63).Test(8));

        rec::DecisionTable Moved(std::move(Table));
        EXPECT_TRUE(Moved.IsSealed());
        EXPECT_TRUE(Moved.CandidatesFor(0x63).Test(8));
    }

    // 捕获生产错误：Set 必须复制位图，调用方 Clear 或复用输入不得篡改已构建索引。
    TEST(DecisionTableTest, SetCopiesBitmapsAcrossSourceClear)
    {
        rec::DecisionTable Table;
        rec::CandidateBitmap Source;
        ASSERT_TRUE(Source.Set(12));
        ASSERT_TRUE(Table.SetFirstByte(0x31, Source));
        ASSERT_TRUE(Table.SetFallback(Source));

        Source.Clear();
        EXPECT_TRUE(Table.CandidatesFor(0x31).Test(12));
        EXPECT_TRUE(Table.Fallback().Test(12));

        rec::CandidateBitmap Replacement;
        ASSERT_TRUE(Replacement.Set(13));
        ASSERT_TRUE(Table.SetFallback(Replacement));
        Replacement.Clear();
        EXPECT_FALSE(Table.Fallback().Test(12));
        EXPECT_TRUE(Table.Fallback().Test(13));
    }

    // 捕获生产错误：发布后仍可写入决策表会使在线 const 查询看到不一致候选集。
    TEST(DecisionTableTest, RejectsMutationsAfterSeal)
    {
        rec::DecisionTable Table;
        rec::CandidateBitmap Initial;
        ASSERT_TRUE(Initial.Set(2));
        ASSERT_TRUE(Table.SetFirstByte(0x41, Initial));
        ASSERT_TRUE(Table.SetFallback(Initial));
        ASSERT_TRUE(Table.SetMinimumBytes(2, 4));
        ASSERT_TRUE(Table.Seal());
        EXPECT_TRUE(Table.IsSealed());
        EXPECT_FALSE(Table.Seal());

        EXPECT_FALSE(Table.AddFirstByte(0x41, 3));
        EXPECT_FALSE(Table.AddFallback(3));
        EXPECT_FALSE(Table.SetFirstByte(0x41, rec::CandidateBitmap{}));
        EXPECT_FALSE(Table.SetFallback(rec::CandidateBitmap{}));
        EXPECT_FALSE(Table.SetMinimumBytes(2, 8));

        const std::array<std::byte, 1> Data{static_cast<std::byte>(0x41)};
        const auto Result = Table.Lookup(Data);
        EXPECT_EQ(Result.State, rec::MatchState::NeedMore);
        EXPECT_TRUE(Result.Candidates.Test(2));
        EXPECT_EQ(Result.RequiredBytes, 4U);
    }

} // namespace
