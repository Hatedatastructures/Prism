/**
 * @file ProbeBufferTest.cpp
 * @brief 增量预读缓冲与固定快照测试
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <initializer_list>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{

    namespace Net = boost::asio;
    using Prism::Recognition::ProbeBuffer;
    using Prism::Recognition::RecognitionStatus;
    using Prism::SharedTransmission;
    using Prism::Transmission;

    /** @brief 创建足以容纳固定探测前缀的测试字节池。 */
    auto MakeProbeBufferBytePool() -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{8U, 4U});
    }

    struct ReadStep
    {
        std::vector<std::byte> Data;
        std::error_code Error;
        std::size_t Count{0};
    };

    class ScriptedTransport final : public Transmission
    {
    public:
        explicit ScriptedTransport(Net::any_io_executor Executor)
            : Prism::Transmission(Executor), Executor_(std::move(Executor))
        {
        }

        void Push(std::vector<std::byte> Data, std::error_code Error = {})
        {
            Steps_.push_back(ReadStep{std::move(Data), Error, 0});
        }

        void PushZeroProgress()
        {
            Steps_.push_back(ReadStep{{}, {}, 0});
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto ReadSizes() const -> const std::vector<std::size_t> &
        {
            return ReadSizes_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            ReadSizes_.push_back(Buffer.size());
            if (Steps_.empty())
            {
                Prism::Transmission::PostResult(Executor_, std::move(Handler), Prism::IoResult{0, {}});
                return;
            }
            auto &Step = Steps_.front();
            std::size_t Count = Step.Count;
            auto Failure = Prism::Fault::Failure{};
            if (Step.Data.empty())
            {
                Failure = Prism::Fault::FromNative(Step.Error);
                Steps_.pop_front();
            }
            else
            {
                Count = (std::min)(Buffer.size(), Step.Data.size());
                std::copy_n(Step.Data.begin(), static_cast<std::ptrdiff_t>(Count), Buffer.begin());
                Step.Data.erase(Step.Data.begin(), Step.Data.begin() + static_cast<std::ptrdiff_t>(Count));
                Failure = Prism::Fault::FromNative(Step.Error);
                if (Step.Data.empty())
                {
                    Steps_.pop_front();
                }
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{Count, std::move(Failure)});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler),
                                                  Prism::IoResult{Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), Prism::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            Canceled_ = true;
            return {};
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

    private:
        Net::any_io_executor Executor_;
        std::deque<ReadStep> Steps_;
        std::size_t ReadCalls_{0};
        std::vector<std::size_t> ReadSizes_;
        bool Closed_{false};
        bool Canceled_{false};
    };

    class OverReportingTransport final : public Transmission
    {
    public:
        explicit OverReportingTransport(Net::any_io_executor Executor)
            : Prism::Transmission(Executor), Executor_(std::move(Executor))
        {
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{Buffer.size() + 1, {}});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler),
                                                  Prism::IoResult{Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), Prism::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            Canceled_ = true;
            return {};
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

    private:
        Net::any_io_executor Executor_;
        std::size_t ReadCalls_{0};
        bool Closed_{false};
        bool Canceled_{false};
    };

    auto Bytes(std::initializer_list<std::uint8_t> Values) -> std::vector<std::byte>
    {
        std::vector<std::byte> Result;
        Result.reserve(Values.size());
        for (const auto Value : Values)
        {
            Result.push_back(static_cast<std::byte>(Value));
        }
        return Result;
    }

    auto RunCoro(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation), [&](std::exception_ptr Error)
                      {
                          Failure = Error;
                      });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /**
     * @brief 验证读出数据同时报错时 ProbeBuffer 保留字节和错误。
     */
    auto RunReadDataAndErrorScenario(
        const std::shared_ptr<ScriptedTransport> &Transport,
        ProbeBuffer &Buffer) -> Net::awaitable<void>
    {
        const auto Result = co_await Buffer.Ensure(*Transport, 4);
        EXPECT_EQ(Result.Status, RecognitionStatus::IoError);
        EXPECT_EQ(Result.Added, 2U);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Buffer.Size(), 2U);
        if (Buffer.Size() == 2U)
        {
            EXPECT_EQ(Buffer.Data()[0], static_cast<std::byte>(0x10));
            EXPECT_EQ(Buffer.Data()[1], static_cast<std::byte>(0x11));
        }
    }

    /**
     * @brief 验证 ProbeBuffer 扩容时旧 snapshot 保持稳定。
     */
    auto RunSnapshotGrowthScenario(
        const std::shared_ptr<ScriptedTransport> &Transport,
        ProbeBuffer &Buffer) -> Net::awaitable<void>
    {
        (void)co_await Buffer.Ensure(*Transport, 2);
        const auto Before = Buffer.Snapshot();
        (void)co_await Buffer.Ensure(*Transport, 4);
        const auto After = Buffer.Snapshot();
        EXPECT_EQ(Before.Size(), 2U);
        EXPECT_EQ(After.Size(), 4U);
        if (Before.Size() == 2U && After.Size() == 4U)
        {
            EXPECT_EQ(Before.Data()[0], static_cast<std::byte>(0x40));
            EXPECT_EQ(Before.Data()[1], static_cast<std::byte>(0x41));
            EXPECT_EQ(After.Data()[2], static_cast<std::byte>(0x42));
            EXPECT_EQ(After.Data()[3], static_cast<std::byte>(0x43));
        }
    }

    /**
     * @brief 验证 replay 先返回预读字节，再交付底层尾部。
     */
    auto RunReplayScenario(
        const std::shared_ptr<ScriptedTransport> &Transport,
        ProbeBuffer &Buffer) -> Net::awaitable<void>
    {
        (void)co_await Buffer.Ensure(*Transport, 3);
        auto Replay = Buffer.Replay(Transport);
        std::array<std::byte, 5> Output{};
        const auto Read = co_await Replay->ReadSome(Output);
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Read.Bytes, 3U);
        if (!Read.Failure.Failed() && Read.Bytes == 3U)
        {
            EXPECT_EQ(Output[0], static_cast<std::byte>(0x50));
            EXPECT_EQ(Output[1], static_cast<std::byte>(0x51));
            EXPECT_EQ(Output[2], static_cast<std::byte>(0x52));
        }
        const auto Tail = co_await Replay->ReadSome(
            std::span<std::byte>(Output).subspan(3));
        EXPECT_FALSE(Tail.Failure.Failed());
        EXPECT_EQ(Tail.Bytes, 2U);
        if (!Tail.Failure.Failed() && Tail.Bytes == 2U)
        {
            EXPECT_EQ(Output[3], static_cast<std::byte>(0x53));
            EXPECT_EQ(Output[4], static_cast<std::byte>(0x54));
        }
    }

    /**
     * @brief 验证空 replay 直接借用底层传输并可在 buffer 销毁后读取。
     */
    auto RunEmptyReplayScenario(const SharedTransmission &Replay) -> Net::awaitable<void>
    {
        std::array<std::byte, 2> Output{};
        const auto Read = co_await Replay->ReadSome(Output);
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Read.Bytes, 2U);
        if (!Read.Failure.Failed() && Read.Bytes == 2U)
        {
            EXPECT_EQ(Output[0], static_cast<std::byte>(0x60));
            EXPECT_EQ(Output[1], static_cast<std::byte>(0x61));
        }
    }

    /** @brief 保存首次读取终态与回放验证所需的测试状态。 */
    struct ReplayFirstTerminalScenario final
    {
        ProbeBuffer &Buffer;
        std::shared_ptr<ScriptedTransport> Transport;
        std::error_code Reset;
        Prism::Recognition::ProbeFillResult Fill{};
        Prism::IoResult PrefixResult{};
        Prism::IoResult FollowingResult{};
        std::array<std::byte, 1> Prefix{};
        std::size_t ReadsAfterEnsure{};
        bool ReplayCreated{};
    };

    /** @brief 捕获 EOF 后执行显式失败回放，并读取前缀及终态。 */
    auto RunReplayKeepsFirstCapturedTerminalScenario(ReplayFirstTerminalScenario &Scenario)
        -> Net::awaitable<void>
    {
        Scenario.Fill = co_await Scenario.Buffer.Ensure(*Scenario.Transport, 2U);
        Scenario.ReadsAfterEnsure = Scenario.Transport->ReadCalls();
        const auto Replay = Scenario.Buffer.Replay(
            Scenario.Transport, Prism::Fault::FromNative(Scenario.Reset));
        Scenario.ReplayCreated = static_cast<bool>(Replay);
        if (Scenario.ReplayCreated)
        {
            Scenario.PrefixResult = co_await (*Replay)->ReadSome(Scenario.Prefix);
            Scenario.FollowingResult = co_await (*Replay)->ReadSome(Scenario.Prefix);
        }
    }

    // 捕获生产错误：分片读若未累计每次返回的字节会丢失预读数据。
    TEST(ProbeBufferTest, ReadsFragmentedInputOnlyToMinimum)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x01}));
        Transport->Push(Bytes({0x02}));
        Transport->Push(Bytes({0x03}));
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 2);
                    EXPECT_EQ(Result.Status, RecognitionStatus::Accepted);
                    EXPECT_EQ(Result.Added, 2U);
                    EXPECT_EQ(Buffer.Size(), 2U);
                    EXPECT_EQ(Transport->ReadCalls(), 2U);
                }());
    }

    TEST(ProbeBufferTest, ReadsAvailableWindowInOneOperation)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x01, 0x02, 0x03}));
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.ReadSome(*Transport, 4);
                    EXPECT_EQ(Result.Status, RecognitionStatus::Accepted);
                    EXPECT_EQ(Result.Added, 3U);
                    EXPECT_EQ(Buffer.Size(), 3U);
                }());

        ASSERT_EQ(Transport->ReadSizes().size(), 1U);
        EXPECT_EQ(Transport->ReadSizes().front(), 4U);
    }

    // 捕获生产错误：读到数据同时报错时若先丢错误会丢失已捕获字节。
    TEST(ProbeBufferTest, PreservesBytesWhenReadReturnsDataAndError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x10, 0x11}), std::make_error_code(std::errc::connection_reset));
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, RunReadDataAndErrorScenario(Transport, Buffer));
    }

    // 捕获生产错误：EOF 后继续尝试读取会造成识别协程忙等。
    TEST(ProbeBufferTest, StopsOnEofWithoutSpinning)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x20}));
        Transport->Push({});
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 4);
                    EXPECT_EQ(Result.Status, RecognitionStatus::EndOfStream);
                    EXPECT_EQ(Result.Added, 1U);
                    EXPECT_EQ(Transport->ReadCalls(), 2U);
                }());
    }

    // 捕获生产错误：零进展返回若未终止会在异常传输上无限循环。
    TEST(ProbeBufferTest, RejectsZeroProgress)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->PushZeroProgress();
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 1);
                    EXPECT_EQ(Result.Status, RecognitionStatus::EndOfStream);
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_EQ(Transport->ReadCalls(), 1U);
                }());
    }

    // 捕获生产错误：超过容量仍发起读会越过识别预算并写坏缓冲区。
    TEST(ProbeBufferTest, RejectsMinimumBeyondCapacityBeforeReading)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x30, 0x31, 0x32, 0x33}));
        ProbeBuffer Buffer(3, MakeProbeBufferBytePool());

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 4);
                    EXPECT_EQ(Result.Status, RecognitionStatus::BudgetExceeded);
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_EQ(Transport->ReadCalls(), 0U);
                    EXPECT_TRUE(Buffer.Empty());
                }());
    }

    // 捕获生产错误：增长缓冲区会使挂起协程持有的 snapshot span 悬垂。
    TEST(ProbeBufferTest, SnapshotRemainsStableAcrossCopyOnWriteGrowth)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x40, 0x41}));
        Transport->Push(Bytes({0x42, 0x43}));
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, RunSnapshotGrowthScenario(Transport, Buffer));
    }

    // 捕获生产错误：回放顺序错误会重复预读数据或跳过底层流字节。
    TEST(ProbeBufferTest, ReplayReturnsBufferedBytesBeforeUnderlyingBytes)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x50, 0x51, 0x52}));
        Transport->Push(Bytes({0x53, 0x54}));
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, RunReplayScenario(Transport, Buffer));
    }

    // 捕获生产错误：超报读长度会导致缓冲区越界或错误地保留未写入字节。
    TEST(ProbeBufferTest, RejectsOverReportedReadWithoutChangingBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<OverReportingTransport>(Io.get_executor());
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 2);
                    EXPECT_EQ(Result.Status, RecognitionStatus::IoError);
                    EXPECT_EQ(Result.Error, std::make_error_code(std::errc::value_too_large));
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_TRUE(Buffer.Empty());
                    EXPECT_EQ(Buffer.Size(), 0U);
                    EXPECT_EQ(Transport->ReadCalls(), 1U);
                }());
    }

    // 捕获生产错误：真实 TCP 的 Fault::Code::Eof 不应被识别为普通 I/O 失败。
    TEST(ProbeBufferTest, ClassifiesExplicitFaultEofAsEndOfStream)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Eof = Prism::Fault::make_error_code(
            Prism::Fault::ToCode(boost::asio::error::eof));
        Transport->Push({}, Eof);
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 1);
                    EXPECT_EQ(Result.Status, RecognitionStatus::EndOfStream);
                    EXPECT_EQ(Result.Error, Eof);
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_EQ(Buffer.Size(), 0U);
                    EXPECT_EQ(Transport->ReadCalls(), 1U);
                }());
    }

    // 捕获生产错误：零字节非 EOF 错误不能被误判为正常流结束。
    TEST(ProbeBufferTest, KeepsNonEofErrorAsIoError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Error = std::make_error_code(std::errc::connection_reset);
        Transport->Push({}, Error);
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 1);
                    EXPECT_EQ(Result.Status, RecognitionStatus::IoError);
                    EXPECT_EQ(Result.Error, Error);
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_TRUE(Buffer.Empty());
                    EXPECT_EQ(Transport->ReadCalls(), 1U);
                }());
    }

    // 捕获生产错误：空预读不应创建悬垂 wrapper，底层传输须在缓冲区销毁后仍可读。
    TEST(ProbeBufferTest, EmptyReplayPassesThroughUnderlyingTransport)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x60, 0x61}));
        SharedTransmission Replay;
        {
            ProbeBuffer Buffer(8, MakeProbeBufferBytePool());
            Replay = Buffer.Replay(Transport);
            EXPECT_EQ(Replay.get(), Transport.get());
        }

        RunCoro(Io, RunEmptyReplayScenario(Replay));
    }

    TEST(ProbeBufferTest, ZeroMaximumReadsDoNotConsumeTransportOrBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x62}));
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());
        Prism::Recognition::ProbeFillResult Fill;
        Prism::Recognition::ProbeReadResult EmptyRead;
        Prism::Recognition::ProbeReadResult Read;
        std::size_t CallsAfterZeroReads = 0;
        bool EmptyAfterZeroReads = false;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Fill = co_await Buffer.ReadSome(*Transport, 0U);
                    EmptyRead = co_await Buffer.ReadSomeWithTerminal(*Transport, 0U);
                    CallsAfterZeroReads = Transport->ReadCalls();
                    EmptyAfterZeroReads = Buffer.Empty();
                    Read = co_await Buffer.ReadSomeWithTerminal(*Transport, 1U);
                    co_return;
                }());

        EXPECT_EQ(Fill.Status, RecognitionStatus::Accepted);
        EXPECT_EQ(Fill.Added, 0U);
        EXPECT_FALSE(Fill.Error);
        EXPECT_EQ(EmptyRead.Status, RecognitionStatus::Accepted);
        EXPECT_EQ(EmptyRead.Added, 0U);
        EXPECT_FALSE(EmptyRead.Failure.Failed());
        EXPECT_EQ(CallsAfterZeroReads, 0U);
        EXPECT_TRUE(EmptyAfterZeroReads);
        EXPECT_EQ(Read.Status, RecognitionStatus::Accepted);
        EXPECT_EQ(Read.Added, 1U);
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Buffer.Data()[0], static_cast<std::byte>(0x62));
        EXPECT_EQ(Transport->ReadCalls(), 1U);
    }

    TEST(ProbeBufferTest, ReplayKeepsFirstCapturedTerminalOverExplicitLaterFailure)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Eof = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        const auto Reset = std::make_error_code(std::errc::connection_reset);
        Transport->Push(Bytes({0x63}), Eof);
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());
        ReplayFirstTerminalScenario Scenario{Buffer, Transport, Reset};

        RunCoro(Io, RunReplayKeepsFirstCapturedTerminalScenario(Scenario));

        const auto &Fill = Scenario.Fill;
        const auto &PrefixResult = Scenario.PrefixResult;
        const auto &FollowingResult = Scenario.FollowingResult;
        const auto &Prefix = Scenario.Prefix;
        const auto ReadsAfterEnsure = Scenario.ReadsAfterEnsure;
        const auto ReplayCreated = Scenario.ReplayCreated;

        ASSERT_TRUE(ReplayCreated);
        EXPECT_EQ(Fill.Status, RecognitionStatus::IoError);
        EXPECT_EQ(Fill.Added, 1U);
        EXPECT_EQ(Fill.Error, Eof);
        EXPECT_EQ(PrefixResult.Bytes, 1U);
        EXPECT_EQ(Prefix[0], static_cast<std::byte>(0x63));
        EXPECT_EQ(PrefixResult.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(PrefixResult.Failure.Native, Eof);
        EXPECT_EQ(FollowingResult.Bytes, 0U);
        EXPECT_EQ(FollowingResult.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(FollowingResult.Failure.Native, Eof);
        EXPECT_EQ(Transport->ReadCalls(), ReadsAfterEnsure);
    }

    TEST(ProbeBufferTest, EmptyReplayReturnsTypedTerminalWithoutConsumingTransport)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Terminal = Prism::Fault::FromNative(Native);
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());

        const auto Replay = Buffer.Replay(Transport, Terminal);

        ASSERT_TRUE(Replay);
        const auto Preview = *Replay;
        const std::span<std::byte> EmptyBuffer;
        std::array<std::byte, 1> ReadBuffer{};
        Prism::IoResult EmptyResult;
        Prism::IoResult TerminalResult;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    EmptyResult = co_await Preview->ReadSome(EmptyBuffer);
                    TerminalResult = co_await Preview->ReadSome(ReadBuffer);
                    co_return;
                }());

        EXPECT_EQ(EmptyResult.Bytes, 0U);
        EXPECT_FALSE(EmptyResult.Failure.Failed());
        EXPECT_EQ(TerminalResult.Bytes, 0U);
        EXPECT_EQ(TerminalResult.Failure.Code, Terminal.Code);
        EXPECT_EQ(TerminalResult.Failure.Native, Native);
        EXPECT_EQ(Transport->ReadCalls(), 0U);
        EXPECT_TRUE(Buffer.Empty());
    }

    TEST(ProbeBufferTest, SeedsProbePrefixBeforeIncrementalGrowth)
    {
        ProbeBuffer Buffer(8, MakeProbeBufferBytePool());
        const auto Prefix = Bytes({0x16, 0x03, 0x03});

        EXPECT_TRUE(Buffer.Seed(Prefix));
        EXPECT_EQ(Buffer.Size(), Prefix.size());
        EXPECT_EQ(Buffer.Data()[0], Prefix[0]);
        EXPECT_FALSE(Buffer.Seed(Bytes({0x00, 0x01, 0x02, 0x03, 0x04, 0x05})));
        EXPECT_EQ(Buffer.Size(), Prefix.size());
    }

} // namespace
