/**
 * @file MuxWriteContract.cpp
 * @brief Mux partial write 和多流 writer 顺序契约测试
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

#include <preview/Protocols/Mux/Session.hpp>
#include <preview/Protocols/Mux/Smux/Codec.hpp>
#include <preview/Protocols/Mux/Smux/Types.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace net = boost::asio;
    using PreviewSession = Preview::Mux::Session<Preview::Mux::Smux::Codec>;

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
        -> net::awaitable<void>
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
                          std::array<std::uint8_t, Size> Payload,
                          std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done)
        -> net::awaitable<void>
    {
        (void)Done->try_send(co_await Session->PushData(StreamId, Payload));
    }

    auto RunSendFinAndSignal(
        std::shared_ptr<PreviewSession> Session,
        std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done) -> net::awaitable<void>
    {
        co_await Session->SendFin(1);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunSendRstAndSignal(
        std::shared_ptr<PreviewSession> Session,
        std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done) -> net::awaitable<void>
    {
        co_await Session->SendRst(3);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunCloseAfterSignals(
        std::shared_ptr<PreviewSession> Session,
        std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done,
        const std::size_t SignalCount) -> net::awaitable<void>
    {
        for (std::size_t Index = 0; Index < SignalCount; ++Index)
        {
            (void)co_await Done->async_receive(net::use_awaitable);
        }
        co_await Session->Close();
    }

    template <std::size_t Size>
    auto RunPushResult(std::shared_ptr<PreviewSession> Session, const std::uint32_t StreamId,
                       std::array<std::uint8_t, Size> Payload, Preview::ProtocolEc *Result)
        -> net::awaitable<void>
    {
        *Result = co_await Session->PushData(StreamId, Payload);
    }

    template <std::size_t Size>
    auto RunPushExpectError(std::shared_ptr<PreviewSession> Session, const std::uint32_t StreamId,
                            std::array<std::uint8_t, Size> Payload, std::error_code *Failure)
        -> net::awaitable<void>
    {
        const auto Ec = co_await Session->PushData(StreamId, Payload);
        if (!Ec)
        {
            *Failure = std::make_error_code(std::errc::protocol_error);
        }
    }

    TEST(MuxWriteContract, CompletesFrameWithSingleByteWrites)
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 1;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const std::array<std::uint8_t, 4> Payload{0x01, 0x02, 0x03, 0x04};

        net::co_spawn(Ioc, RunPushData(Session, 1, Payload, &Failure, true),
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
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->WriteLimitSequence = {1, 3, 2, 1, 4};
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const std::array<std::uint8_t, 9> Payload{0x21, 0x22, 0x23, 0x24, 0x25,
                                                   0x26, 0x27, 0x28, 0x29};

        net::co_spawn(Ioc, RunPushData(Session, 1, Payload, &Failure, true),
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
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 2;
        auto Session = PreviewSession::Create(Transport, {});
        auto Done = std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(
            Ioc.get_executor(), 2);

        net::co_spawn(Ioc, RunPushAndSignal(Session, 1, std::array<std::uint8_t, 3>{0xA1, 0xA2, 0xA3}, Done),
                      net::detached);
        net::co_spawn(Ioc, RunPushAndSignal(Session, 3, std::array<std::uint8_t, 2>{0xB1, 0xB2}, Done),
                      net::detached);

        std::exception_ptr Failure;
        net::co_spawn(Ioc, RunCloseAfterSignals(Session, Done, 2),
            [&](std::exception_ptr Error)
            {
                Failure = std::move(Error);
                Ioc.stop();
            });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const std::array<std::uint8_t, 3> FirstPayload{0xA1, 0xA2, 0xA3};
        const std::array<std::uint8_t, 2> SecondPayload{0xB1, 0xB2};
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
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->FailNextWrite = true;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;

        net::co_spawn(Ioc, RunPushExpectError(Session, 1, std::array<std::uint8_t, 2>{0xC1, 0xC2}, &Failure),
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
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 2;
        Transport->WriteFailAt = 2;
        auto Session = PreviewSession::Create(Transport, {});
        Preview::ProtocolEc Result;

        net::co_spawn(Ioc,
                      RunPushResult(Session, 1, std::array<std::uint8_t, 4>{0xE1, 0xE2, 0xE3, 0xE4}, &Result),
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
        const std::array<std::uint8_t, 4> Payload{0xE1, 0xE2, 0xE3, 0xE4};
        const auto Expected = Preview::Mux::Smux::Codec::BuildData(1, Payload);
        ASSERT_GE(Expected.size(), 2u);
        EXPECT_EQ(Transport->Written,
                  std::vector<std::uint8_t>(Expected.begin(), Expected.begin() + 2));
    }

    TEST(MuxWriteContract, RejectsWriteCountBeyondRemainingFrame)
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->OverreportWrite = true;
        auto Session = PreviewSession::Create(Transport, {});
        Preview::ProtocolEc Result;

        net::co_spawn(Ioc, RunPushResult(Session, 1, std::array<std::uint8_t, 1>{0xF1}, &Result),
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
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 2;
        auto Session = PreviewSession::Create(Transport, {});
        auto Done = std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(
            Ioc.get_executor(), 3);

        net::co_spawn(Ioc, RunPushAndSignal(Session, 1, std::array<std::uint8_t, 3>{0x11, 0x12, 0x13}, Done),
                      net::detached);
        net::co_spawn(Ioc, RunSendFinAndSignal(Session, Done), net::detached);
        net::co_spawn(Ioc, RunSendRstAndSignal(Session, Done), net::detached);

        std::exception_ptr Failure;
        net::co_spawn(Ioc, RunCloseAfterSignals(Session, Done, 3),
            [&](std::exception_ptr Error)
            {
                Failure = std::move(Error);
                Ioc.stop();
            });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const std::array<std::uint8_t, 3> Payload{0x11, 0x12, 0x13};
        const auto Data = Preview::Mux::Smux::Codec::BuildData(1, Payload);
        const auto Fin = Preview::Mux::Smux::Codec::BuildFin(1);
        const auto Rst = Preview::Mux::Smux::Codec::BuildRst(3);
        EXPECT_TRUE(FramesAreConcatenated(Transport->Written, {Data, Fin, Rst}));
    }

    TEST(MuxWriteContract, TreatsZeroProgressAsWriteFailure)
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->ZeroWrite = true;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;

        net::co_spawn(Ioc, RunPushExpectError(Session, 1, std::array<std::uint8_t, 1>{0xD1}, &Failure),
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

} // namespace
