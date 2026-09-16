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
#include <initializer_list>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::Recognition::ProbeBuffer;
    using Preview::Recognition::RecognitionStatus;
    using Preview::SharedTransmission;
    using Preview::Transmission;

    struct ReadStep
    {
        std::vector<std::byte> Data;
        std::error_code Error;
        std::size_t Count{0};
    };

    class ScriptedTransport final : public Transmission
    {
    public:
        explicit ScriptedTransport(Net::any_io_executor Executor) : Executor_(std::move(Executor)) {}

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

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            ++ReadCalls_;
            ReadSizes_.push_back(Buffer.size());
            Error.clear();
            if (Steps_.empty())
            {
                co_return 0;
            }
            auto &Step = Steps_.front();
            if (Step.Data.empty())
            {
                Error = Step.Error;
                Steps_.pop_front();
                co_return Step.Count;
            }
            const auto Count = (std::min)(Buffer.size(), Step.Data.size());
            std::copy_n(Step.Data.begin(), static_cast<std::ptrdiff_t>(Count), Buffer.begin());
            Step.Data.erase(Step.Data.begin(), Step.Data.begin() + static_cast<std::ptrdiff_t>(Count));
            Error = Step.Error;
            if (Step.Data.empty())
            {
                Steps_.pop_front();
            }
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            co_return Buffer.size();
        }

        void Close() override
        {
            Closed_ = true;
        }

        void Cancel() override
        {
            Canceled_ = true;
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
        explicit OverReportingTransport(Net::any_io_executor Executor) : Executor_(std::move(Executor)) {}

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            ++ReadCalls_;
            Error.clear();
            co_return Buffer.size() + 1;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            co_return Buffer.size();
        }

        void Close() override
        {
            Closed_ = true;
        }

        void Cancel() override
        {
            Canceled_ = true;
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

    template <typename Coro>
    auto RunCoro(Net::io_context &Io, Coro &&CoroFactory) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::forward<Coro>(CoroFactory)(), [&](std::exception_ptr Error)
                      {
                          Failure = Error;
                          Io.stop();
                      });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
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
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 2);
                    EXPECT_EQ(Result.Status, RecognitionStatus::Accepted);
                    EXPECT_EQ(Result.Added, 2U);
                    EXPECT_EQ(Buffer.Size(), 2U);
                    EXPECT_EQ(Transport->ReadCalls(), 2U);
                });
    }

    TEST(ProbeBufferTest, ReadsAvailableWindowInOneOperation)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x01, 0x02, 0x03}));
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.ReadSome(*Transport, 4);
                    EXPECT_EQ(Result.Status, RecognitionStatus::Accepted);
                    EXPECT_EQ(Result.Added, 3U);
                    EXPECT_EQ(Buffer.Size(), 3U);
                });

        ASSERT_EQ(Transport->ReadSizes().size(), 1U);
        EXPECT_EQ(Transport->ReadSizes().front(), 4U);
    }

    // 捕获生产错误：读到数据同时报错时若先丢错误会丢失已捕获字节。
    TEST(ProbeBufferTest, PreservesBytesWhenReadReturnsDataAndError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x10, 0x11}), std::make_error_code(std::errc::connection_reset));
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
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
                });
    }

    // 捕获生产错误：EOF 后继续尝试读取会造成识别协程忙等。
    TEST(ProbeBufferTest, StopsOnEofWithoutSpinning)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x20}));
        Transport->Push({});
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 4);
                    EXPECT_EQ(Result.Status, RecognitionStatus::EndOfStream);
                    EXPECT_EQ(Result.Added, 1U);
                    EXPECT_EQ(Transport->ReadCalls(), 2U);
                });
    }

    // 捕获生产错误：零进展返回若未终止会在异常传输上无限循环。
    TEST(ProbeBufferTest, RejectsZeroProgress)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->PushZeroProgress();
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 1);
                    EXPECT_EQ(Result.Status, RecognitionStatus::EndOfStream);
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_EQ(Transport->ReadCalls(), 1U);
                });
    }

    // 捕获生产错误：超过容量仍发起读会越过识别预算并写坏缓冲区。
    TEST(ProbeBufferTest, RejectsMinimumBeyondCapacityBeforeReading)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x30, 0x31, 0x32, 0x33}));
        ProbeBuffer Buffer(3);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 4);
                    EXPECT_EQ(Result.Status, RecognitionStatus::BudgetExceeded);
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_EQ(Transport->ReadCalls(), 0U);
                    EXPECT_TRUE(Buffer.Empty());
                });
    }

    // 捕获生产错误：增长缓冲区会使挂起协程持有的 snapshot span 悬垂。
    TEST(ProbeBufferTest, SnapshotRemainsStableAcrossCopyOnWriteGrowth)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x40, 0x41}));
        Transport->Push(Bytes({0x42, 0x43}));
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
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
                });
    }

    // 捕获生产错误：回放顺序错误会重复预读数据或跳过底层流字节。
    TEST(ProbeBufferTest, ReplayReturnsBufferedBytesBeforeUnderlyingBytes)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x50, 0x51, 0x52}));
        Transport->Push(Bytes({0x53, 0x54}));
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    (void)co_await Buffer.Ensure(*Transport, 3);
                    auto Replay = Buffer.Replay(Transport);
                    std::array<std::byte, 5> Output{};
                    std::error_code Error;
                    const auto Read = co_await Replay->async_read_some(Output, Error);
                    EXPECT_FALSE(Error);
                    EXPECT_EQ(Read, 3U);
                    if (!Error && Read == 3U)
                    {
                        EXPECT_EQ(Output[0], static_cast<std::byte>(0x50));
                        EXPECT_EQ(Output[1], static_cast<std::byte>(0x51));
                        EXPECT_EQ(Output[2], static_cast<std::byte>(0x52));
                    }
                    const auto Tail = co_await Replay->async_read_some(
                        std::span<std::byte>(Output).subspan(3), Error);
                    EXPECT_FALSE(Error);
                    EXPECT_EQ(Tail, 2U);
                    if (!Error && Tail == 2U)
                    {
                        EXPECT_EQ(Output[3], static_cast<std::byte>(0x53));
                        EXPECT_EQ(Output[4], static_cast<std::byte>(0x54));
                    }
                });
    }

    // 捕获生产错误：超报读长度会导致缓冲区越界或错误地保留未写入字节。
    TEST(ProbeBufferTest, RejectsOverReportedReadWithoutChangingBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<OverReportingTransport>(Io.get_executor());
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 2);
                    EXPECT_EQ(Result.Status, RecognitionStatus::IoError);
                    EXPECT_EQ(Result.Error, std::make_error_code(std::errc::value_too_large));
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_TRUE(Buffer.Empty());
                    EXPECT_EQ(Buffer.Size(), 0U);
                    EXPECT_EQ(Transport->ReadCalls(), 1U);
                });
    }

    // 捕获生产错误：真实 TCP 的 Fault::Code::Eof 不应被识别为普通 I/O 失败。
    TEST(ProbeBufferTest, ClassifiesExplicitFaultEofAsEndOfStream)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Eof = Preview::Fault::make_error_code(
            Preview::Fault::ToCode(boost::asio::error::eof));
        Transport->Push({}, Eof);
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 1);
                    EXPECT_EQ(Result.Status, RecognitionStatus::EndOfStream);
                    EXPECT_EQ(Result.Error, Eof);
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_EQ(Buffer.Size(), 0U);
                    EXPECT_EQ(Transport->ReadCalls(), 1U);
                });
    }

    // 捕获生产错误：零字节非 EOF 错误不能被误判为正常流结束。
    TEST(ProbeBufferTest, KeepsNonEofErrorAsIoError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Error = std::make_error_code(std::errc::connection_reset);
        Transport->Push({}, Error);
        ProbeBuffer Buffer(8);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Buffer.Ensure(*Transport, 1);
                    EXPECT_EQ(Result.Status, RecognitionStatus::IoError);
                    EXPECT_EQ(Result.Error, Error);
                    EXPECT_EQ(Result.Added, 0U);
                    EXPECT_TRUE(Buffer.Empty());
                    EXPECT_EQ(Transport->ReadCalls(), 1U);
                });
    }

    // 捕获生产错误：空预读不应创建悬垂 wrapper，底层传输须在缓冲区销毁后仍可读。
    TEST(ProbeBufferTest, EmptyReplayPassesThroughUnderlyingTransport)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0x60, 0x61}));
        SharedTransmission Replay;
        {
            ProbeBuffer Buffer(8);
            Replay = Buffer.Replay(Transport);
            EXPECT_EQ(Replay.get(), Transport.get());
        }

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    std::array<std::byte, 2> Output{};
                    std::error_code Error;
                    const auto Read = co_await Replay->async_read_some(Output, Error);
                    EXPECT_FALSE(Error);
                    EXPECT_EQ(Read, 2U);
                    if (!Error && Read == 2U)
                    {
                        EXPECT_EQ(Output[0], static_cast<std::byte>(0x60));
                        EXPECT_EQ(Output[1], static_cast<std::byte>(0x61));
                    }
                });
    }

    TEST(ProbeBufferTest, SeedsProbePrefixBeforeIncrementalGrowth)
    {
        ProbeBuffer Buffer(8);
        const auto Prefix = Bytes({0x16, 0x03, 0x03});

        EXPECT_TRUE(Buffer.Seed(Prefix));
        EXPECT_EQ(Buffer.Size(), Prefix.size());
        EXPECT_EQ(Buffer.Data()[0], Prefix[0]);
        EXPECT_FALSE(Buffer.Seed(Bytes({0x00, 0x01, 0x02, 0x03, 0x04, 0x05})));
        EXPECT_EQ(Buffer.Size(), Prefix.size());
    }

} // namespace
