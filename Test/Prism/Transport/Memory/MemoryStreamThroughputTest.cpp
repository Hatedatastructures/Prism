/**
 * @file MemoryStreamThroughputTest.cpp
 * @brief MemoryStream 上 Prism typed throughput runner 的消费契约。
 * @details 保留完整往返字节数、方向计数、报告速率与普通 Fault 值断言。
 */

#include "../Core/TransportResources.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <exception>
#include <utility>

#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Benchmark/Bench.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;

    /** @brief 驱动单个吞吐测量协程并传播真实协程异常。 */
    auto RunCoro(Net::io_context &Context, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Context.restart();
        Net::co_spawn(Context, std::move(Operation), [&Failure](std::exception_ptr Error)
                      { Failure = std::move(Error); });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 保留原 16 MiB 与 64 KiB Block 输入并输出 typed 测量值。 */
    auto RunMemoryThroughput(Prism::Testing::OwnedTransportPair &Pair,
                             Prism::PrismBenchResult &Result) -> Net::awaitable<void>
    {
        Prism::BenchOptions Options;
        Options.Total = 16 * 1024 * 1024;
        Options.Block = 64 * 1024;
        Result = co_await Prism::BenchPrismThroughput(*Pair.FirstOwner, *Pair.SecondOwner, Options);
    }
}

TEST(Transport, BenchThroughputMemory)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    Prism::PrismBenchResult Result{};
    RunCoro(Io, RunMemoryThroughput(Pair, Result));
    EXPECT_EQ(Result.Report.Bytes, 16U * 1024U * 1024U);
    EXPECT_TRUE(Result.BytesWritten == Result.Report.Bytes &&
                Result.BytesRead == Result.Report.Bytes);
    EXPECT_GT(Result.Report.Mbps, 0.0);
    EXPECT_TRUE(Result.Failure.Succeeded());
    Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Io, Pair.FirstOwner));
    Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Io, Pair.SecondOwner));
}
