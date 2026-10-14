/**
 * @file MuxWriteContractLifecycle.cpp
 * @brief Mux 写入屏障、排队与取消生命周期测试
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
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
#include <Preview/Protocols/Mux/Smux/Detail/Wire/Codec.hpp>
#include <Preview/Protocols/Mux/Smux/Detail/Wire/Types.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>

namespace
{

    namespace Net = boost::asio;
    using PreviewSession = Preview::Mux::Session<Preview::Mux::Smux::Detail::Codec>;
    using ErrorChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using SharedErrorChannel = std::shared_ptr<ErrorChannel>;
    using SmallPayload = std::array<std::uint8_t, 2>;

    auto StopWithException(Net::io_context &Ioc, std::exception_ptr &Failure,
                           std::exception_ptr Error) -> void
    {
        Failure = std::move(Error);
        Ioc.stop();
    }

    class ThrowingWriteTransport final : public Preview::Transmission
    {
    public:
        explicit ThrowingWriteTransport(Net::any_io_executor Ex)
            : Preview::Transmission(Ex), Ex_(std::move(Ex)),
              ReadWake_(Ex_, 1), WriteEntered_(Ex_, 1), WriteGate_(Ex_, 1)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Ex_; }
        [[nodiscard]] auto IsOpen() const -> bool override { return !Closed_; }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(
                ReadInput{std::static_pointer_cast<ThrowingWriteTransport>(
                              Preview::Transmission::shared_from_this()),
                          Buffer},
                std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(
                WriteInput{std::static_pointer_cast<ThrowingWriteTransport>(
                               Preview::Transmission::shared_from_this()),
                           Buffer},
                std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Ex_, std::move(Handler), Preview::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            (void)ReadWake_.try_send(boost::system::error_code{});
            (void)WriteGate_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto WaitWriteEntered() -> Net::awaitable<void>
        {
            co_await WriteEntered_.async_receive(Net::use_awaitable);
        }

        auto ReleaseWrite() -> void
        {
            (void)WriteGate_.try_send(boost::system::error_code{});
        }

    private:
        struct ReadInput final
        {
            std::shared_ptr<ThrowingWriteTransport> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<ThrowingWriteTransport> Owner;
            std::span<const std::byte> Buffer;
        };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto ReadPartial() -> Net::awaitable<Preview::IoResult>
        {
            boost::system::error_code WakeError;
            co_await ReadWake_.async_receive(Net::redirect_error(Net::use_awaitable, WakeError));
            co_return Preview::IoResult{
                0, Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::UnexpectedEof))};
        }
        [[nodiscard]] auto WritePartial() -> Net::awaitable<Preview::IoResult>
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

        Net::any_io_executor Ex_;
        ErrorChannel ReadWake_;
        ErrorChannel WriteEntered_;
        ErrorChannel WriteGate_;
        bool WriteEnteredFlag_{false};
        bool Closed_{false};
    };

    /// 首次写入可挂起的真实 Transmission，用于验证 producer cancel/close 竞态。
    class BlockingWriteTransport final : public Preview::Transmission
    {
    public:
        explicit BlockingWriteTransport(Net::any_io_executor Ex)
            : Preview::Transmission(Ex), Ex_(std::move(Ex)),
              ReadWake_(Ex_, 1), WriteEntered_(Ex_, 1), WriteGate_(Ex_, 1)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Ex_; }
        [[nodiscard]] auto IsOpen() const -> bool override { return !Closed_; }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(
                ReadInput{std::static_pointer_cast<BlockingWriteTransport>(
                              Preview::Transmission::shared_from_this()),
                          Buffer},
                std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(
                WriteInput{std::static_pointer_cast<BlockingWriteTransport>(
                               Preview::Transmission::shared_from_this()),
                           Buffer},
                std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Ex_, std::move(Handler), Preview::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            (void)WriteGate_.try_send(boost::system::error_code{});
            (void)ReadWake_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            (void)WriteGate_.try_send(boost::system::error_code{});
            (void)ReadWake_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto WaitWriteEntered() -> Net::awaitable<void>
        {
            co_await WriteEntered_.async_receive(Net::use_awaitable);
        }

        auto ReleaseWrite() -> void
        {
            (void)WriteGate_.try_send(boost::system::error_code{});
        }

        std::vector<std::uint8_t> Written;

    private:
        struct ReadInput final
        {
            std::shared_ptr<BlockingWriteTransport> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<BlockingWriteTransport> Owner;
            std::span<const std::byte> Buffer;
        };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto ReadPartial() -> Net::awaitable<Preview::IoResult>
        {
            boost::system::error_code WakeError;
            co_await ReadWake_.async_receive(Net::redirect_error(Net::use_awaitable, WakeError));
            co_return Preview::IoResult{
                0, Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::UnexpectedEof))};
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (!WriteEnteredFlag_)
            {
                WriteEnteredFlag_ = true;
                (void)WriteEntered_.try_send(boost::system::error_code{});
            }
            boost::system::error_code GateError;
            co_await WriteGate_.async_receive(Net::redirect_error(Net::use_awaitable, GateError));
            if (Closed_)
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::BrokenPipe))};
            }
            const auto *Bytes = reinterpret_cast<const std::uint8_t *>(Buffer.data());
            Written.insert(Written.end(), Bytes, Bytes + Buffer.size());
            co_return Preview::IoResult{Buffer.size(), {}};
        }

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

    struct PushSignalRequest final
    {
        std::shared_ptr<PreviewSession> Session;
        std::uint32_t StreamId;
        std::array<std::uint8_t, Size> Payload;
        SharedErrorChannel Done;
    };

    template <std::size_t Size>
    auto RunPushAndSignal(PushSignalRequest<Size> Request) -> Net::awaitable<void>
    {
        (void)Request.Done->try_send(
            co_await Request.Session->PushData(Request.StreamId, Request.Payload));
    }

    template <std::size_t Size>
    struct PushStoreRequest final
    {
        std::shared_ptr<PreviewSession> Session;
        std::uint32_t StreamId;
        std::array<std::uint8_t, Size> Payload;
        Preview::ProtocolEc *Result;
        SharedErrorChannel Done;
    };

    template <std::size_t Size>
    auto RunPushAndStore(PushStoreRequest<Size> Request) -> Net::awaitable<void>
    {
        *Request.Result = co_await Request.Session->PushData(Request.StreamId, Request.Payload);
        (void)Request.Done->try_send(boost::system::error_code{});
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

    struct CancelAndReleaseRequest final
    {
        Net::io_context &Ioc;
        std::shared_ptr<PreviewSession> Session;
        SharedBlockingWriteTransport Transport;
        std::shared_ptr<Net::cancellation_signal> CancelSignal;
        SharedErrorChannel CanceledDone;
        SharedErrorChannel SecondDone;
        SmallPayload SecondPayload;
    };

    auto RunCancelAndRelease(CancelAndReleaseRequest Request) -> Net::awaitable<void>
    {
        co_await Request.Transport->WaitWriteEntered();
        Net::co_spawn(Request.Ioc,
                      RunSecondPush(Request.Session, Request.SecondDone, Request.SecondPayload),
                      Net::detached);
        // 让第二个 producer 把请求排入 writer 队列。
        co_await Net::post(Request.Ioc, Net::use_awaitable);
        co_await Net::post(Request.Ioc, Net::use_awaitable);
        Request.CancelSignal->emit(Net::cancellation_type::all);
        co_await Net::post(Request.Ioc, Net::use_awaitable);
        (void)co_await Request.CanceledDone->async_receive(Net::use_awaitable);
        Request.Transport->ReleaseWrite();
        Request.Transport->ReleaseWrite();

        Net::steady_timer Deadline(Request.Ioc);
        Deadline.expires_after(std::chrono::milliseconds(200));
        using Net::experimental::awaitable_operators::operator||;
        auto Completion = Request.SecondDone->async_receive(Net::use_awaitable) ||
                          Deadline.async_wait(Net::use_awaitable);
        const auto Result = co_await std::move(Completion);
        EXPECT_EQ(Result.index(), 0U) << "writer waited for canceled producer Consumed";
        co_await Request.Session->Close();
    }

    struct BudgetFirstRequest final
    {
        std::shared_ptr<PreviewSession> Session;
        SmallPayload Payload;
        Preview::ProtocolEc *Result;
        SharedErrorChannel Done;
    };

    auto RunBudgetFirstPush(BudgetFirstRequest Request) -> Net::awaitable<void>
    {
        *Request.Result = co_await Request.Session->PushData(1, Request.Payload);
        (void)Request.Done->try_send(boost::system::error_code{});
    }

    struct BudgetSecondRequest final
    {
        std::shared_ptr<PreviewSession> Session;
        SharedBlockingWriteTransport Transport;
        SharedErrorChannel FirstDone;
        Preview::ProtocolEc *FirstResult;
        SmallPayload Payload;
    };

    auto RunBudgetSecondPush(BudgetSecondRequest Request) -> Net::awaitable<void>
    {
        co_await Request.Transport->WaitWriteEntered();
        const auto Second = co_await Request.Session->PushData(3, Request.Payload);
        EXPECT_EQ(Second, Preview::make_error_code(Preview::Error::BadLength));

        Request.Transport->ReleaseWrite();
        co_await Request.FirstDone->async_receive(Net::use_awaitable);
        EXPECT_FALSE(*Request.FirstResult);
        co_await Request.Session->Close();
    }

    struct WriterExceptionRequest final
    {
        Net::io_context &Ioc;
        std::shared_ptr<PreviewSession> Session;
        std::shared_ptr<ThrowingWriteTransport> Transport;
        SharedErrorChannel Done;
        SmallPayload FirstPayload;
        SmallPayload SecondPayload;
        bool &TimedOut;
        std::array<Preview::ProtocolEc, 2> &Results;
    };

    /// 验证 writer 异常后排队请求都收到失败结果并完成关闭。
    auto RunWriterExceptionScenario(WriterExceptionRequest Request)
        -> Net::awaitable<void>
    {
        Net::co_spawn(Request.Ioc,
                      RunPushAndStore(PushStoreRequest{
                          Request.Session, 1, Request.FirstPayload,
                          &Request.Results[0], Request.Done}),
                      Net::detached);
        Net::co_spawn(Request.Ioc,
                      RunPushAndStore(PushStoreRequest{
                          Request.Session, 3, Request.SecondPayload,
                          &Request.Results[1], Request.Done}),
                      Net::detached);

        co_await Request.Transport->WaitWriteEntered();
        co_await Net::post(Request.Ioc, Net::use_awaitable);
        co_await Net::post(Request.Ioc, Net::use_awaitable);
        Request.Transport->ReleaseWrite();

        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Deadline(Request.Ioc);
        Deadline.expires_after(std::chrono::milliseconds(200));
        auto First = co_await (Request.Done->async_receive(Net::use_awaitable) ||
                               Deadline.async_wait(Net::use_awaitable));
        if (First.index() != 0U)
        {
            Request.TimedOut = true;
            co_await Request.Session->Close();
            co_return;
        }
        Deadline.expires_after(std::chrono::milliseconds(200));
        auto Second = co_await (Request.Done->async_receive(Net::use_awaitable) ||
                                Deadline.async_wait(Net::use_awaitable));
        if (Second.index() != 0U)
        {
            Request.TimedOut = true;
            co_await Request.Session->Close();
            co_return;
        }
        co_await Request.Session->Close();
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

        Net::co_spawn(Ioc, RunPushAndSignal(PushSignalRequest{Session, 1, FirstPayload, Done}), Net::detached);
        Net::co_spawn(Ioc, RunPushAndSignal(PushSignalRequest{Session, 3, SecondPayload, Done}), Net::detached);

        std::exception_ptr Failure;
        Net::co_spawn(Ioc, RunCloseAfterSignals(Session, Done, 2),
                      [&](std::exception_ptr Error)
                      { StopWithException(Ioc, Failure, Error); });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const auto First = Preview::Mux::Smux::Detail::Codec::BuildData(1, FirstPayload);
        const auto Second = Preview::Mux::Smux::Detail::Codec::BuildData(3, SecondPayload);
        std::vector<std::uint8_t> FirstThenSecond = First;
        FirstThenSecond.insert(FirstThenSecond.end(), Second.begin(), Second.end());
        std::vector<std::uint8_t> SecondThenFirst = Second;
        SecondThenFirst.insert(SecondThenFirst.end(), First.begin(), First.end());
        EXPECT_TRUE(Transport->Written == FirstThenSecond || Transport->Written == SecondThenFirst);
    }


    TEST(MuxWriteContract, SerializesConcurrentDataFinAndRstFrames)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 2;
        auto Session = PreviewSession::Create(Transport, {});
        auto Done = std::make_shared<ErrorChannel>(Ioc.get_executor(), 3);
        const std::array<std::uint8_t, 3> Payload{0x11, 0x12, 0x13};

        Net::co_spawn(Ioc, RunPushAndSignal(PushSignalRequest{Session, 1, Payload, Done}), Net::detached);
        Net::co_spawn(Ioc, RunSendFinAndSignal(Session, Done), Net::detached);
        Net::co_spawn(Ioc, RunSendRstAndSignal(Session, Done), Net::detached);

        std::exception_ptr Failure;
        Net::co_spawn(Ioc, RunCloseAfterSignals(Session, Done, 3),
                      [&](std::exception_ptr Error)
                      { StopWithException(Ioc, Failure, Error); });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const auto Data = Preview::Mux::Smux::Detail::Codec::BuildData(1, Payload);
        const auto Fin = Preview::Mux::Smux::Detail::Codec::BuildFin(1);
        const auto Rst = Preview::Mux::Smux::Detail::Codec::BuildRst(3);
        EXPECT_TRUE(FramesAreConcatenated(Transport->Written, {Data, Fin, Rst}));
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
                      RunCancelAndRelease(CancelAndReleaseRequest{
                          Ioc, Session, Transport, CancelSignal, CanceledDone, SecondDone, SecondPayload}),
                      [&](std::exception_ptr Error)
                      { StopWithException(Ioc, Failure, Error); });
        Ioc.run();
        ASSERT_FALSE(Failure);
    }

    TEST(MuxWriteContract, RejectsQueuedWritesBeyondSessionBudget)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<BlockingWriteTransport>(Ioc.get_executor());
        Preview::Mux::SessionOptions Options{};
        Options.MaxPendingWriteBytes = Preview::Mux::Smux::Detail::FrameHdrsize + 2;
        auto Session = PreviewSession::Create(Transport, Options);
        auto FirstDone = std::make_shared<ErrorChannel>(Ioc.get_executor(), 1);
        Preview::ProtocolEc FirstResult;

        const SmallPayload FirstPayload{0xC1, 0xC2};
        const SmallPayload SecondPayload{0xD1, 0xD2};
        Net::co_spawn(Ioc,
                      RunBudgetFirstPush(BudgetFirstRequest{Session, FirstPayload, &FirstResult, FirstDone}),
                      Net::detached);

        std::exception_ptr Failure;
        Net::co_spawn(Ioc,
                      RunBudgetSecondPush(BudgetSecondRequest{
                          Session, Transport, FirstDone, &FirstResult, SecondPayload}),
                      [&](std::exception_ptr Error)
                      { StopWithException(Ioc, Failure, Error); });
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

        std::exception_ptr Failure;
        Net::co_spawn(Ioc, RunWriterExceptionScenario(WriterExceptionRequest{
                          Ioc, Session, Transport, Done, FirstPayload, SecondPayload,
                          TimedOut, Results}),
                      [&](std::exception_ptr Error)
                      { StopWithException(Ioc, Failure, Error); });
        Ioc.run();

        ASSERT_FALSE(Failure);
        EXPECT_FALSE(TimedOut);
        EXPECT_EQ(Results[0], Preview::make_error_code(Preview::Error::IoError));
        EXPECT_EQ(Results[1], Preview::make_error_code(Preview::Error::IoError));
        EXPECT_FALSE(Session->IsOpen());
    }

} // namespace
