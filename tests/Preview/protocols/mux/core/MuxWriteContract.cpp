/**
 * @file MuxWriteContract.cpp
 * @brief Mux partial write 和多流 writer 顺序契约测试
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <Preview/Protocols/Mux/Session.hpp>
#include <Preview/Protocols/Mux/SessionReadLoop.hpp>
#include <Preview/Protocols/Mux/Smux/Codec.hpp>
#include <Preview/Protocols/Mux/Smux/Types.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;
    using PreviewSession = Preview::Mux::Session<Preview::Mux::Smux::Codec>;
    using ErrorChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using SharedErrorChannel = std::shared_ptr<ErrorChannel>;
    using SmallPayload = std::array<std::uint8_t, 2>;

    class ThrowingWriteTransport final : public Preview::Transmission
    {
    public:
        explicit ThrowingWriteTransport(Net::any_io_executor Ex)
            : Ex_(std::move(Ex)), ReadWake_(Ex_, 1), WriteEntered_(Ex_, 1), WriteGate_(Ex_, 1)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Ex_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            boost::system::error_code WakeError;
            co_await ReadWake_.async_receive(Net::redirect_error(Net::use_awaitable, WakeError));
            ErrorCode = Preview::make_error_code(Preview::Error::UnexpectedEof);
            co_return 0;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &)
            -> Net::awaitable<std::size_t> override
        {
            if (!WriteEnteredFlag_)
            {
                WriteEnteredFlag_ = true;
                (void)WriteEntered_.try_send(boost::system::error_code{});
            }
            boost::system::error_code GateError;
            co_await WriteGate_.async_receive(Net::redirect_error(Net::use_awaitable, GateError));
            throw std::runtime_error("injected writer exception");
        }

        [[nodiscard]] auto WaitWriteEntered() -> Net::awaitable<void>
        {
            co_await WriteEntered_.async_receive(Net::use_awaitable);
        }

        auto ReleaseWrite() -> void
        {
            (void)WriteGate_.try_send(boost::system::error_code{});
        }

        auto Close() -> void override
        {
            Closed_ = true;
            (void)ReadWake_.try_send(boost::system::error_code{});
            (void)WriteGate_.try_send(boost::system::error_code{});
        }

        auto Cancel() -> void override
        {
            Closed_ = true;
        }

    private:
        Net::any_io_executor Ex_;
        ErrorChannel ReadWake_;
        ErrorChannel WriteEntered_;
        ErrorChannel WriteGate_;
        bool WriteEnteredFlag_{false};
        bool Closed_{false};
    };

    auto RunRejectsOverreportedRead(std::shared_ptr<Preview::PreviewMockTransport> Raw,
                                    std::array<std::uint8_t, 4> &Buffer) -> Net::awaitable<void>
    {
        const auto Ok = co_await Preview::Mux::Detail::ReadExact(Raw, Buffer);
        EXPECT_FALSE(Ok);
        EXPECT_EQ(Raw->ReadsDone, 1u);
    }

    TEST(MuxReadLoop, RejectsOverreportedRead)
    {
        Net::io_context Ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Raw->OverreportRead = true;
        std::array<std::uint8_t, 4> Buffer{};

        Net::co_spawn(Ioc, RunRejectsOverreportedRead(Raw, Buffer), Net::detached);
        Ioc.run();
    }

    /// 首次写入可挂起的真实 Transmission，用于验证 producer cancel/close 竞态。
    class BlockingWriteTransport final : public Preview::Transmission
    {
    public:
        explicit BlockingWriteTransport(Net::any_io_executor Ex)
            : Ex_(std::move(Ex)), ReadWake_(Ex_, 1), WriteEntered_(Ex_, 1), WriteGate_(Ex_, 1)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Ex_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &Ec)
            -> Net::awaitable<std::size_t> override
        {
            boost::system::error_code WakeError;
            co_await ReadWake_.async_receive(Net::redirect_error(Net::use_awaitable, WakeError));
            Ec = make_error_code(Preview::Error::UnexpectedEof);
            co_return 0;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Ec)
            -> Net::awaitable<std::size_t> override
        {
            Ec.clear();
            if (!WriteEnteredFlag_)
            {
                WriteEnteredFlag_ = true;
                (void)WriteEntered_.try_send(boost::system::error_code{});
            }
            boost::system::error_code GateError;
            co_await WriteGate_.async_receive(Net::redirect_error(Net::use_awaitable, GateError));
            if (Closed_)
            {
                Ec = make_error_code(Preview::Error::BrokenPipe);
                co_return 0;
            }
            const auto *Bytes = reinterpret_cast<const std::uint8_t *>(Buffer.data());
            Written.insert(Written.end(), Bytes, Bytes + Buffer.size());
            co_return Buffer.size();
        }

        [[nodiscard]] auto WaitWriteEntered() -> Net::awaitable<void>
        {
            co_await WriteEntered_.async_receive(Net::use_awaitable);
        }

        auto ReleaseWrite() -> void
        {
            (void)WriteGate_.try_send(boost::system::error_code{});
        }

        auto Close() -> void override
        {
            Closed_ = true;
            (void)WriteGate_.try_send(boost::system::error_code{});
            (void)ReadWake_.try_send(boost::system::error_code{});
        }

        auto Cancel() -> void override
        {
            (void)WriteGate_.try_send(boost::system::error_code{});
            (void)ReadWake_.try_send(boost::system::error_code{});
        }

        std::vector<std::uint8_t> Written;

    private:
        Net::any_io_executor Ex_;
        ErrorChannel ReadWake_;
        ErrorChannel WriteEntered_;
        ErrorChannel WriteGate_;
        bool WriteEnteredFlag_{false};
        bool Closed_{false};
    };

    using SharedBlockingWriteTransport = std::shared_ptr<BlockingWriteTransport>;

    [[nodiscard]] auto FramesAreConcatenated(
        const std::vector<std::uint8_t> &Wire,
        const std::array<std::vector<std::uint8_t>, 3> &Frames) -> bool
    {
        std::array<bool, 3> Used{};
        std::size_t Offset = 0;
        for (std::size_t Count = 0; Count < Frames.size(); ++Count)
        {
            bool Found = false;
            for (std::size_t Index = 0; Index < Frames.size(); ++Index)
            {
                if (Used[Index] || Frames[Index].size() > Wire.size() - Offset)
                {
                    continue;
                }
                if (!std::equal(Frames[Index].begin(), Frames[Index].end(), Wire.begin() + Offset))
                {
                    continue;
                }
                Used[Index] = true;
                Offset += Frames[Index].size();
                Found = true;
                break;
            }
            if (!Found)
            {
                return false;
            }
        }
        return Offset == Wire.size();
    }

    template <std::size_t Size>
    auto RunPushData(std::shared_ptr<PreviewSession> Session, const std::uint32_t StreamId,
                     std::array<std::uint8_t, Size> Payload, std::error_code *Failure, const bool Close)
        -> Net::awaitable<void>
    {
        const auto Ec = co_await Session->PushData(StreamId, Payload);
        if (Ec)
        {
            *Failure = std::error_code(Ec.value(), std::generic_category());
        }
        if (Close)
        {
            co_await Session->Close();
        }
    }

    template <std::size_t Size>
    auto RunPushAndSignal(std::shared_ptr<PreviewSession> Session, const std::uint32_t StreamId,
                          std::array<std::uint8_t, Size> Payload, SharedErrorChannel Done)
        -> Net::awaitable<void>
    {
        (void)Done->try_send(co_await Session->PushData(StreamId, Payload));
    }

    template <std::size_t Size>
    auto RunPushAndStore(std::shared_ptr<PreviewSession> Session, const std::uint32_t StreamId,
                         std::array<std::uint8_t, Size> Payload, Preview::ProtocolEc *Result,
                         SharedErrorChannel Done) -> Net::awaitable<void>
    {
        *Result = co_await Session->PushData(StreamId, Payload);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunSendFinAndSignal(
        std::shared_ptr<PreviewSession> Session,
        SharedErrorChannel Done) -> Net::awaitable<void>
    {
        co_await Session->SendFin(1);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunSendRstAndSignal(
        std::shared_ptr<PreviewSession> Session,
        SharedErrorChannel Done) -> Net::awaitable<void>
    {
        co_await Session->SendRst(3);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunCloseAfterSignals(
        std::shared_ptr<PreviewSession> Session,
        SharedErrorChannel Done,
        const std::size_t SignalCount) -> Net::awaitable<void>
    {
        for (std::size_t Index = 0; Index < SignalCount; ++Index)
        {
            (void)co_await Done->async_receive(Net::use_awaitable);
        }
        co_await Session->Close();
    }

    auto RunCanceledProducer(std::shared_ptr<PreviewSession> Session,
                             SmallPayload Payload, SharedErrorChannel Done) -> Net::awaitable<void>
    {
        try
        {
            (void)co_await Session->PushData(1, Payload);
        }
        catch (...)
        {
            // 取消是本测试的预期路径；RawWrite 必须收口并释放共享请求。
        }
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunSecondPush(std::shared_ptr<PreviewSession> Session,
                       SharedErrorChannel Done, SmallPayload Payload) -> Net::awaitable<void>
    {
        const auto Ec = co_await Session->PushData(3, Payload);
        (void)Done->try_send(Ec);
    }

    auto RunCancelAndRelease(
        Net::io_context &Ioc, std::shared_ptr<PreviewSession> Session,
        SharedBlockingWriteTransport Transport,
        std::shared_ptr<Net::cancellation_signal> CancelSignal,
        SharedErrorChannel CanceledDone,
        SharedErrorChannel SecondDone,
        SmallPayload SecondPayload) -> Net::awaitable<void>
    {
        co_await Transport->WaitWriteEntered();
        Net::co_spawn(Ioc, RunSecondPush(Session, SecondDone, SecondPayload), Net::detached);
        // 让第二个 producer 把请求排入 writer 队列。
        co_await Net::post(Ioc, Net::use_awaitable);
        co_await Net::post(Ioc, Net::use_awaitable);
        CancelSignal->emit(Net::cancellation_type::all);
        co_await Net::post(Ioc, Net::use_awaitable);
        (void)co_await CanceledDone->async_receive(Net::use_awaitable);
        Transport->ReleaseWrite();
        Transport->ReleaseWrite();

        Net::steady_timer Deadline(Ioc);
        Deadline.expires_after(std::chrono::milliseconds(200));
        using Net::experimental::awaitable_operators::operator||;
        auto Completion = SecondDone->async_receive(Net::use_awaitable) ||
                          Deadline.async_wait(Net::use_awaitable);
        const auto Result = co_await std::move(Completion);
        EXPECT_EQ(Result.index(), 0U) << "writer waited for canceled producer Consumed";
        co_await Session->Close();
    }

    template <std::size_t Size>
    auto RunPushResult(std::shared_ptr<PreviewSession> Session, const std::uint32_t StreamId,
                       std::array<std::uint8_t, Size> Payload, Preview::ProtocolEc *Result)
        -> Net::awaitable<void>
    {
        *Result = co_await Session->PushData(StreamId, Payload);
    }

    template <std::size_t Size>
    auto RunPushExpectError(std::shared_ptr<PreviewSession> Session, const std::uint32_t StreamId,
                            std::array<std::uint8_t, Size> Payload, std::error_code *Failure)
        -> Net::awaitable<void>
    {
        const auto Ec = co_await Session->PushData(StreamId, Payload);
        if (!Ec)
        {
            *Failure = std::make_error_code(std::errc::protocol_error);
        }
    }

    auto RunBudgetFirstPush(
        std::shared_ptr<PreviewSession> Session, SmallPayload Payload,
        Preview::ProtocolEc *Result, SharedErrorChannel Done)
        -> Net::awaitable<void>
    {
        *Result = co_await Session->PushData(1, Payload);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunBudgetSecondPush(
        std::shared_ptr<PreviewSession> Session, SharedBlockingWriteTransport Transport,
        SharedErrorChannel FirstDone, Preview::ProtocolEc *FirstResult,
        SmallPayload Payload) -> Net::awaitable<void>
    {
        co_await Transport->WaitWriteEntered();
        const auto Second = co_await Session->PushData(3, Payload);
        EXPECT_EQ(Second, Preview::make_error_code(Preview::Error::BadLength));

        Transport->ReleaseWrite();
        co_await FirstDone->async_receive(Net::use_awaitable);
        EXPECT_FALSE(*FirstResult);
        co_await Session->Close();
    }

    TEST(MuxWriteContract, CompletesFrameWithSingleByteWrites)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 1;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const std::array<std::uint8_t, 4> Payload{0x01, 0x02, 0x03, 0x04};

        Net::co_spawn(Ioc, RunPushData(Session, 1, Payload, &Failure, true),
            [&](std::exception_ptr Error)
            {
                if (Error)
                {
                    Failure = std::make_error_code(std::errc::io_error);
                }
                Ioc.stop();
            });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const auto Expected = Preview::Mux::Smux::Codec::BuildData(1, Payload);
        EXPECT_EQ(Transport->Written, Expected);
    }

    TEST(MuxWriteContract, CompletesFrameWithVaryingShortWrites)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->WriteLimitSequence = {1, 3, 2, 1, 4};
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const std::array<std::uint8_t, 9> Payload{0x21, 0x22, 0x23, 0x24, 0x25,
                                                   0x26, 0x27, 0x28, 0x29};

        Net::co_spawn(Ioc, RunPushData(Session, 1, Payload, &Failure, true),
            [&](std::exception_ptr Error)
            {
                if (Error)
                {
                    Failure = std::make_error_code(std::errc::io_error);
                }
                Ioc.stop();
            });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const auto Expected = Preview::Mux::Smux::Codec::BuildData(1, Payload);
        EXPECT_EQ(Transport->Written, Expected);
    }

    TEST(MuxWriteContract, SerializesConcurrentStreamFrames)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 2;
        auto Session = PreviewSession::Create(Transport, {});
        auto Done = std::make_shared<ErrorChannel>(Ioc.get_executor(), 2);
        const std::array<std::uint8_t, 3> FirstPayload{0xA1, 0xA2, 0xA3};
        const SmallPayload SecondPayload{0xB1, 0xB2};

        Net::co_spawn(Ioc, RunPushAndSignal(Session, 1, FirstPayload, Done), Net::detached);
        Net::co_spawn(Ioc, RunPushAndSignal(Session, 3, SecondPayload, Done), Net::detached);

        std::exception_ptr Failure;
        Net::co_spawn(Ioc, RunCloseAfterSignals(Session, Done, 2),
            [&](std::exception_ptr Error)
            {
                Failure = std::move(Error);
                Ioc.stop();
            });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const auto First = Preview::Mux::Smux::Codec::BuildData(1, FirstPayload);
        const auto Second = Preview::Mux::Smux::Codec::BuildData(3, SecondPayload);
        std::vector<std::uint8_t> FirstThenSecond = First;
        FirstThenSecond.insert(FirstThenSecond.end(), Second.begin(), Second.end());
        std::vector<std::uint8_t> SecondThenFirst = Second;
        SecondThenFirst.insert(SecondThenFirst.end(), First.begin(), First.end());
        EXPECT_TRUE(Transport->Written == FirstThenSecond || Transport->Written == SecondThenFirst);
    }

    TEST(MuxWriteContract, PropagatesWriteErrorAndClosesSession)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->FailNextWrite = true;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const SmallPayload Payload{0xC1, 0xC2};

        Net::co_spawn(Ioc, RunPushExpectError(Session, 1, Payload, &Failure),
            [&](std::exception_ptr Error)
            {
                if (Error)
                {
                    Failure = std::make_error_code(std::errc::io_error);
                }
                Ioc.stop();
            });
        Ioc.run();

        EXPECT_FALSE(Failure);
        EXPECT_TRUE(Transport->IsClosed());
        EXPECT_FALSE(Session->IsOpen());
    }

    TEST(MuxWriteContract, PropagatesPartialWriteThenError)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 2;
        Transport->WriteFailAt = 2;
        auto Session = PreviewSession::Create(Transport, {});
        Preview::ProtocolEc Result;
        const std::array<std::uint8_t, 4> Payload{0xE1, 0xE2, 0xE3, 0xE4};

        Net::co_spawn(Ioc,
                      RunPushResult(Session, 1, Payload, &Result),
            [&](std::exception_ptr Error)
            {
                if (Error)
                {
                    Result = Preview::make_error_code(Preview::Error::IoError);
                }
                Ioc.stop();
            });
        Ioc.run();

        EXPECT_EQ(Result, Preview::make_error_code(Preview::Error::IoError));
        EXPECT_TRUE(Transport->IsClosed());
        const auto Expected = Preview::Mux::Smux::Codec::BuildData(1, Payload);
        ASSERT_GE(Expected.size(), 2u);
        EXPECT_EQ(Transport->Written,
                  std::vector<std::uint8_t>(Expected.begin(), Expected.begin() + 2));
    }

    TEST(MuxWriteContract, RejectsWriteCountBeyondRemainingFrame)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->OverreportWrite = true;
        auto Session = PreviewSession::Create(Transport, {});
        Preview::ProtocolEc Result;
        const std::array<std::uint8_t, 1> Payload{0xF1};

        Net::co_spawn(Ioc, RunPushResult(Session, 1, Payload, &Result),
            [&](std::exception_ptr Error)
            {
                if (Error)
                {
                    Result = Preview::make_error_code(Preview::Error::IoError);
                }
                Ioc.stop();
            });
        Ioc.run();

        EXPECT_EQ(Result, Preview::make_error_code(Preview::Error::BrokenPipe));
        EXPECT_TRUE(Transport->IsClosed());
        EXPECT_TRUE(Transport->Written.empty());
    }

    TEST(MuxWriteContract, SerializesConcurrentDataFinAndRstFrames)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 2;
        auto Session = PreviewSession::Create(Transport, {});
        auto Done = std::make_shared<ErrorChannel>(Ioc.get_executor(), 3);
        const std::array<std::uint8_t, 3> Payload{0x11, 0x12, 0x13};

        Net::co_spawn(Ioc, RunPushAndSignal(Session, 1, Payload, Done), Net::detached);
        Net::co_spawn(Ioc, RunSendFinAndSignal(Session, Done), Net::detached);
        Net::co_spawn(Ioc, RunSendRstAndSignal(Session, Done), Net::detached);

        std::exception_ptr Failure;
        Net::co_spawn(Ioc, RunCloseAfterSignals(Session, Done, 3),
            [&](std::exception_ptr Error)
            {
                Failure = std::move(Error);
                Ioc.stop();
            });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const auto Data = Preview::Mux::Smux::Codec::BuildData(1, Payload);
        const auto Fin = Preview::Mux::Smux::Codec::BuildFin(1);
        const auto Rst = Preview::Mux::Smux::Codec::BuildRst(3);
        EXPECT_TRUE(FramesAreConcatenated(Transport->Written, {Data, Fin, Rst}));
    }

    TEST(MuxWriteContract, TreatsZeroProgressAsWriteFailure)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->ZeroWrite = true;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const std::array<std::uint8_t, 1> Payload{0xD1};

        Net::co_spawn(Ioc, RunPushExpectError(Session, 1, Payload, &Failure),
            [&](std::exception_ptr Error)
            {
                if (Error)
                {
                    Failure = std::make_error_code(std::errc::io_error);
                }
                Ioc.stop();
            });
        Ioc.run();

        EXPECT_FALSE(Failure);
        EXPECT_TRUE(Transport->IsClosed());
    }

    TEST(MuxWriteContract, CanceledProducerDoesNotBlockFollowingWrites)
    {
        // P-H17：首个 producer 在 writer 已开始写入时被取消，writer 不能再等待
        // 一个永远不会到达的 Consumed 确认；后续排队帧必须在释放底层写入后完成。
        Net::io_context Ioc;
        auto Transport = std::make_shared<BlockingWriteTransport>(Ioc.get_executor());
        auto Session = PreviewSession::Create(Transport, {});
        auto CancelSignal = std::make_shared<Net::cancellation_signal>();
        auto CanceledDone = std::make_shared<ErrorChannel>(Ioc.get_executor(), 1);
        auto SecondDone = std::make_shared<ErrorChannel>(Ioc.get_executor(), 1);

        const SmallPayload FirstPayload{0xA1, 0xA2};
        const SmallPayload SecondPayload{0xB1, 0xB2};
        Net::co_spawn(Ioc, RunCanceledProducer(Session, FirstPayload, CanceledDone),
                      Net::bind_cancellation_slot(CancelSignal->slot(), Net::detached));

        std::exception_ptr Failure;
        Net::co_spawn(Ioc,
                      RunCancelAndRelease(Ioc, Session, Transport, CancelSignal, CanceledDone, SecondDone,
                                          SecondPayload),
                      [&](std::exception_ptr Error)
                      {
                          Failure = std::move(Error);
                          Ioc.stop();
                      });
        Ioc.run();
        ASSERT_FALSE(Failure);
    }

    TEST(MuxWriteContract, RejectsQueuedWritesBeyondSessionBudget)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<BlockingWriteTransport>(Ioc.get_executor());
        Preview::Mux::SessionOptions Options{};
        Options.MaxPendingWriteBytes = Preview::Mux::Smux::FrameHdrsize + 2;
        auto Session = PreviewSession::Create(Transport, Options);
        auto FirstDone = std::make_shared<ErrorChannel>(Ioc.get_executor(), 1);
        Preview::ProtocolEc FirstResult;

        const SmallPayload FirstPayload{0xC1, 0xC2};
        const SmallPayload SecondPayload{0xD1, 0xD2};
        Net::co_spawn(Ioc,
                      RunBudgetFirstPush(Session, FirstPayload, &FirstResult, FirstDone),
                      Net::detached);

        std::exception_ptr Failure;
        Net::co_spawn(Ioc,
                      RunBudgetSecondPush(Session, Transport, FirstDone, &FirstResult, SecondPayload),
                      [&](std::exception_ptr Error)
                      {
                          Failure = std::move(Error);
                          Ioc.stop();
                      });
        Ioc.run();

        EXPECT_FALSE(Failure);
    }

    TEST(MuxWriteContract, CompletesQueuedWritesAfterWriterException)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<ThrowingWriteTransport>(Ioc.get_executor());
        auto Session = PreviewSession::Create(Transport, {});
        auto Done = std::make_shared<ErrorChannel>(Ioc.get_executor(), 2);
        const SmallPayload FirstPayload{0xE1U, 0xE2U};
        const SmallPayload SecondPayload{0xF1U, 0xF2U};
        bool TimedOut = false;
        std::array<Preview::ProtocolEc, 2> Results{};

        auto TestCoroutine = [&]() -> Net::awaitable<void>
        {
            Net::co_spawn(Ioc, RunPushAndStore(Session, 1, FirstPayload, &Results[0], Done), Net::detached);
            Net::co_spawn(Ioc, RunPushAndStore(Session, 3, SecondPayload, &Results[1], Done), Net::detached);

            co_await Transport->WaitWriteEntered();
            co_await Net::post(Ioc, Net::use_awaitable);
            co_await Net::post(Ioc, Net::use_awaitable);
            Transport->ReleaseWrite();

            using Net::experimental::awaitable_operators::operator||;
            Net::steady_timer Deadline(Ioc);
            Deadline.expires_after(std::chrono::milliseconds(200));
            auto First = co_await (Done->async_receive(Net::use_awaitable) ||
                                   Deadline.async_wait(Net::use_awaitable));
            if (First.index() != 0U)
            {
                TimedOut = true;
                co_await Session->Close();
                co_return;
            }
            Deadline.expires_after(std::chrono::milliseconds(200));
            auto Second = co_await (Done->async_receive(Net::use_awaitable) ||
                                    Deadline.async_wait(Net::use_awaitable));
            if (Second.index() != 0U)
            {
                TimedOut = true;
                co_await Session->Close();
                co_return;
            }
            co_await Session->Close();
        };

        std::exception_ptr Failure;
        Net::co_spawn(Ioc, std::move(TestCoroutine),
                      [&](std::exception_ptr Error)
                      {
                          Failure = std::move(Error);
                          Ioc.stop();
                      });
        Ioc.run();

        ASSERT_FALSE(Failure);
        EXPECT_FALSE(TimedOut);
        EXPECT_EQ(Results[0], Preview::make_error_code(Preview::Error::IoError));
        EXPECT_EQ(Results[1], Preview::make_error_code(Preview::Error::IoError));
        EXPECT_FALSE(Session->IsOpen());
    }

} // namespace
