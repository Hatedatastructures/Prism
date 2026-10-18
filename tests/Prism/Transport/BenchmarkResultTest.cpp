/**
 * @file BenchmarkResultTest.cpp
 * @brief 验证 Prism typed benchmark 的实际字节、失败与 I/O 启动边界。
 * @details 使用真实 Transmission 前门驱动脚本化 typed completion，核对同次部分进度与 Failure。
 */

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <cstddef>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;

    /**
     * @brief 单方向 I/O completion 序列；耗尽后明确返回 IoError。
     * @details Writes 与 Reads 分别由同一真实 Transmission 的写入和读取前门消费。
     */
    struct BenchmarkIoScript final
    {
        std::vector<Prism::IoResult> Writes;
        std::vector<Prism::IoResult> Reads;
    };

    /**
     * @brief 经过 Transmission 预约和 completion 路径的脚本化叶子载体。
     * @details 脚本只控制每次真实 StartRead/StartWrite 的返回值，并记录调用次数与写入窗口。
     */
    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        ScriptedTransmission(Net::any_io_executor Executor, BenchmarkIoScript Script)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              WriteScript_(std::move(Script.Writes)), ReadScript_(std::move(Script.Reads))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto WriteCalls() const noexcept -> std::size_t
        {
            return WriteRequests_.size();
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto WriteWindows() const noexcept
            -> const std::vector<std::size_t> &
        {
            return WriteRequests_;
        }

    private:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            const auto Result = Next(ReadScript_, ReadIndex_);
            const auto Count = (std::min)(Buffer.size(), Result.Bytes);
            std::fill_n(Buffer.begin(), Count, std::byte{0x5a});
            std::move(Handler)(Result);
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            WriteRequests_.push_back(Buffer.size());
            const auto Result = Next(WriteScript_, WriteIndex_);
            std::move(Handler)(Result);
        }

        [[nodiscard]] static auto Next(
            const std::vector<Prism::IoResult> &Script,
            std::size_t &Index) -> Prism::IoResult
        {
            if (Index >= Script.size())
            {
                return {0, {Prism::Fault::Code::IoError}};
            }
            return Script[Index++];
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            std::move(Handler)(Prism::IoResult{});
        }

        Net::any_io_executor Executor_;
        std::vector<Prism::IoResult> WriteScript_;
        std::vector<Prism::IoResult> ReadScript_;
        std::vector<std::size_t> WriteRequests_;
        std::size_t WriteIndex_{0};
        std::size_t ReadIndex_{0};
        std::size_t ReadCalls_{0};
    };

    struct BenchmarkRun final
    {
        Prism::PrismBenchResult Result;
        bool CloseAccepted{false};
        bool Drained{false};
    };

    /**
     * @brief 执行一次 typed benchmark 并等待测试载体实际关闭。
     * @param Script 由当前测试独占的叶子 Transmission。
     * @param Options 当前用例的总量和块大小。
     * @return 基准结果以及 Close 接管和 Activity drain 的独立事实。
     */
    auto RunBenchmarkAndClose(
        const std::shared_ptr<ScriptedTransmission> &Script,
        Prism::BenchOptions Options) -> Net::awaitable<BenchmarkRun>
    {
        BenchmarkRun Run;
        Run.Result = co_await Prism::BenchPrismThroughput(*Script, *Script, Options);
        const auto CloseResult = Script->Close();
        Run.CloseAccepted = CloseResult.has_value();
        if (!CloseResult)
        {
            co_return Run;
        }
        const auto DrainResult = co_await Script->Activity()->Drain();
        Run.Drained = DrainResult.has_value();
        co_return Run;
    }

    template <typename OperationFactory>
    auto RunCoroutine(
        Net::io_context &IoContext,
        OperationFactory &&OperationFactoryValue) -> void
    {
        std::exception_ptr Exception;
        IoContext.restart();
        Net::co_spawn(IoContext, std::forward<OperationFactory>(OperationFactoryValue)(),
                      [&Exception](std::exception_ptr Error)
                      { Exception = std::move(Error); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto ExpectClosed(const BenchmarkRun &Run) -> void
    {
        EXPECT_TRUE(Run.CloseAccepted);
        EXPECT_TRUE(Run.Drained);
    }

    TEST(BenchmarkResult, PreservesPartialBytesAndNativeFailure)
    {
        Net::io_context IoContext;
        const auto Native = std::make_error_code(std::errc::connection_aborted);
        BenchmarkIoScript ScriptValue;
        ScriptValue.Writes.push_back(
            {2, {Prism::Fault::Code::ConnectionAborted, Native}});
        auto Script = std::make_shared<ScriptedTransmission>(
            IoContext.get_executor(), std::move(ScriptValue));
        Prism::BenchOptions Options;
        Options.Total = 4;
        Options.Block = 4;
        BenchmarkRun Run;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                     { Run = co_await RunBenchmarkAndClose(Script, Options); });

        ExpectClosed(Run);
        EXPECT_EQ(Script->WriteCalls(), 1U);
        EXPECT_EQ(Script->ReadCalls(), 0U);
        EXPECT_EQ(Script->WriteWindows(), (std::vector<std::size_t>{4U}));
        EXPECT_EQ(Run.Result.BytesWritten, 2U);
        EXPECT_EQ(Run.Result.BytesRead, 0U);
        EXPECT_EQ(Run.Result.Report.Bytes, 0U);
        EXPECT_EQ(Run.Result.Report.Samples, 0U);
        EXPECT_EQ(Run.Result.Failure.Code, Prism::Fault::Code::ConnectionAborted);
        EXPECT_EQ(Run.Result.Failure.Native.category(), Native.category());
        EXPECT_EQ(Run.Result.Failure.Native.value(), Native.value());
    }

    TEST(BenchmarkResult, WriteFailureDoesNotStartRead)
    {
        Net::io_context IoContext;
        const auto Native = std::make_error_code(std::errc::connection_refused);
        BenchmarkIoScript ScriptValue;
        ScriptValue.Writes = {
            {2, {}},
            {0, {Prism::Fault::Code::ConnectionRefused, Native}}};
        auto Script = std::make_shared<ScriptedTransmission>(
            IoContext.get_executor(), std::move(ScriptValue));
        Prism::BenchOptions Options;
        Options.Total = 4;
        Options.Block = 4;
        BenchmarkRun Run;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                     { Run = co_await RunBenchmarkAndClose(Script, Options); });

        ExpectClosed(Run);
        EXPECT_EQ(Script->WriteCalls(), 2U);
        EXPECT_EQ(Script->ReadCalls(), 0U);
        EXPECT_EQ(Script->WriteWindows(), (std::vector<std::size_t>{4U, 2U}));
        EXPECT_EQ(Run.Result.BytesWritten, 2U);
        EXPECT_EQ(Run.Result.BytesRead, 0U);
        EXPECT_EQ(Run.Result.Report.Bytes, 0U);
        EXPECT_EQ(Run.Result.Failure.Code, Prism::Fault::Code::ConnectionRefused);
        EXPECT_EQ(Run.Result.Failure.Native.category(), Native.category());
        EXPECT_EQ(Run.Result.Failure.Native.value(), Native.value());
    }

    TEST(BenchmarkResult, ReadFailureKeepsDirectionalPartialProgress)
    {
        Net::io_context IoContext;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        BenchmarkIoScript ScriptValue;
        ScriptValue.Writes = {{4, {}}, {4, {}}};
        ScriptValue.Reads = {
            {4, {}},
            {2, {Prism::Fault::Code::ConnectionReset, Native}}};
        auto Script = std::make_shared<ScriptedTransmission>(
            IoContext.get_executor(), std::move(ScriptValue));
        Prism::BenchOptions Options;
        Options.Total = 8;
        Options.Block = 4;
        BenchmarkRun Run;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                     { Run = co_await RunBenchmarkAndClose(Script, Options); });

        ExpectClosed(Run);
        EXPECT_EQ(Script->WriteCalls(), 2U);
        EXPECT_EQ(Script->ReadCalls(), 2U);
        EXPECT_EQ(Run.Result.BytesWritten, 8U);
        EXPECT_EQ(Run.Result.BytesRead, 6U);
        EXPECT_EQ(Run.Result.Report.Bytes, 4U);
        EXPECT_EQ(Run.Result.Report.Samples, 1U);
        EXPECT_EQ(Run.Result.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Run.Result.Failure.Native.category(), Native.category());
        EXPECT_EQ(Run.Result.Failure.Native.value(), Native.value());
    }

    TEST(BenchmarkResult, ZeroWriteProgressReturnsIoErrorOnce)
    {
        Net::io_context IoContext;
        BenchmarkIoScript ScriptValue;
        ScriptValue.Writes = {{0, {}}};
        auto Script = std::make_shared<ScriptedTransmission>(
            IoContext.get_executor(), std::move(ScriptValue));
        Prism::BenchOptions Options;
        Options.Total = 1;
        Options.Block = 1;
        BenchmarkRun Run;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                     { Run = co_await RunBenchmarkAndClose(Script, Options); });

        ExpectClosed(Run);
        EXPECT_EQ(Script->WriteCalls(), 1U);
        EXPECT_EQ(Script->ReadCalls(), 0U);
        EXPECT_EQ(Run.Result.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_FALSE(Run.Result.Failure.Native);
        EXPECT_EQ(Run.Result.BytesWritten, 0U);
        EXPECT_EQ(Run.Result.Report.Bytes, 0U);
    }

    TEST(BenchmarkResult, ZeroBlockRejectsWithoutStartingIo)
    {
        Net::io_context IoContext;
        auto Script = std::make_shared<ScriptedTransmission>(
            IoContext.get_executor(), BenchmarkIoScript{});
        Prism::BenchOptions Options;
        Options.Total = 1;
        Options.Block = 0;
        BenchmarkRun Run;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                     { Run = co_await RunBenchmarkAndClose(Script, Options); });

        ExpectClosed(Run);
        EXPECT_EQ(Script->WriteCalls(), 0U);
        EXPECT_EQ(Script->ReadCalls(), 0U);
        EXPECT_EQ(Run.Result.Failure.Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_EQ(Run.Result.BytesWritten, 0U);
        EXPECT_EQ(Run.Result.BytesRead, 0U);
        EXPECT_EQ(Run.Result.Report.Bytes, 0U);
    }

} // namespace
