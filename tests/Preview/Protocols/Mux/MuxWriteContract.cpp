/**
 * @file MuxWriteContract.cpp
 * @brief Mux 写入短写与错误传播契约测试
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

namespace
{

    namespace Net = boost::asio;
    using PreviewSession = Preview::Mux::Session<Preview::Mux::Smux::Detail::Codec>;
    using ErrorChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using SharedErrorChannel = std::shared_ptr<ErrorChannel>;
    using SmallPayload = std::array<std::uint8_t, 2>;

    auto StopWithSystemError(Net::io_context &Ioc, std::error_code &Failure,
                             std::exception_ptr Error) -> void
    {
        if (Error)
        {
            Failure = std::make_error_code(std::errc::io_error);
        }
        Ioc.stop();
    }

    auto StopWithProtocolError(Net::io_context &Ioc, Preview::ProtocolEc &Result,
                               std::exception_ptr Error) -> void
    {
        if (Error)
        {
            Result = Preview::make_error_code(Preview::Error::IoError);
        }
        Ioc.stop();
    }

    auto RunRejectsOverreportedRead(std::shared_ptr<Preview::PreviewMockTransport> Raw,
                                    std::array<std::uint8_t, 4> &Buffer) -> Net::awaitable<void>
    {
        const auto Read = co_await Raw->ReadExact(std::as_writable_bytes(std::span(Buffer)));
        const auto Ok = Read.Failure.Succeeded();
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


    struct PushDataRequest final
    {
        std::shared_ptr<PreviewSession> Session;
        std::uint32_t StreamId;
        std::array<std::uint8_t, Size> Payload;
        std::error_code *Failure;
        bool Close;
    };

    template <std::size_t Size>
    auto RunPushData(PushDataRequest<Size> Request) -> Net::awaitable<void>
    {
        const auto Ec = co_await Request.Session->PushData(Request.StreamId, Request.Payload);
        if (Ec)
        {
            *Request.Failure = std::error_code(Ec.value(), std::generic_category());
        }
        if (Request.Close)
        {
            co_await Request.Session->Close();
        }
    }

    struct PushResultRequest final
    {
        std::shared_ptr<PreviewSession> Session;
        std::uint32_t StreamId;
        std::array<std::uint8_t, Size> Payload;
        Preview::ProtocolEc *Result;
    };

    template <std::size_t Size>
    auto RunPushResult(PushResultRequest<Size> Request) -> Net::awaitable<void>
    {
        *Request.Result = co_await Request.Session->PushData(Request.StreamId, Request.Payload);
    }

    struct PushErrorRequest final
    {
        std::shared_ptr<PreviewSession> Session;
        std::uint32_t StreamId;
        std::array<std::uint8_t, Size> Payload;
        std::error_code *Failure;
    };

    template <std::size_t Size>
    auto RunPushExpectError(PushErrorRequest<Size> Request) -> Net::awaitable<void>
    {
        const auto Ec = co_await Request.Session->PushData(Request.StreamId, Request.Payload);
        if (!Ec)
        {
            *Request.Failure = std::make_error_code(std::errc::protocol_error);
        }
    }

    TEST(MuxWriteContract, CompletesFrameWithSingleByteWrites)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 1;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const std::array<std::uint8_t, 4> Payload{0x01, 0x02, 0x03, 0x04};

        Net::co_spawn(Ioc, RunPushData(PushDataRequest{Session, 1, Payload, &Failure, true}),
                      [&](std::exception_ptr Error)
                      { StopWithSystemError(Ioc, Failure, Error); });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const auto Expected = Preview::Mux::Smux::Detail::Codec::BuildData(1, Payload);
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

        Net::co_spawn(Ioc, RunPushData(PushDataRequest{Session, 1, Payload, &Failure, true}),
                      [&](std::exception_ptr Error)
                      { StopWithSystemError(Ioc, Failure, Error); });
        Ioc.run();

        ASSERT_FALSE(Failure);
        const auto Expected = Preview::Mux::Smux::Detail::Codec::BuildData(1, Payload);
        EXPECT_EQ(Transport->Written, Expected);
    }


    TEST(MuxWriteContract, PropagatesWriteErrorAndClosesSession)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->FailNextWrite = true;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const SmallPayload Payload{0xC1, 0xC2};

        Net::co_spawn(Ioc, RunPushExpectError(PushErrorRequest{Session, 1, Payload, &Failure}),
                      [&](std::exception_ptr Error)
                      { StopWithSystemError(Ioc, Failure, Error); });
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
                      RunPushResult(PushResultRequest{Session, 1, Payload, &Result}),
                      [&](std::exception_ptr Error)
                      { StopWithProtocolError(Ioc, Result, Error); });
        Ioc.run();

        EXPECT_EQ(Result, Preview::make_error_code(Preview::Error::IoError));
        EXPECT_TRUE(Transport->IsClosed());
        const auto Expected = Preview::Mux::Smux::Detail::Codec::BuildData(1, Payload);
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

        Net::co_spawn(Ioc, RunPushResult(PushResultRequest{Session, 1, Payload, &Result}),
                      [&](std::exception_ptr Error)
                      { StopWithProtocolError(Ioc, Result, Error); });
        Ioc.run();

        EXPECT_EQ(Result, Preview::make_error_code(Preview::Error::BrokenPipe));
        EXPECT_TRUE(Transport->IsClosed());
        EXPECT_TRUE(Transport->Written.empty());
    }


    TEST(MuxWriteContract, TreatsZeroProgressAsWriteFailure)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->ZeroWrite = true;
        auto Session = PreviewSession::Create(Transport, {});
        std::error_code Failure;
        const std::array<std::uint8_t, 1> Payload{0xD1};

        Net::co_spawn(Ioc, RunPushExpectError(PushErrorRequest{Session, 1, Payload, &Failure}),
                      [&](std::exception_ptr Error)
                      { StopWithSystemError(Ioc, Failure, Error); });
        Ioc.run();

        EXPECT_FALSE(Failure);
        EXPECT_TRUE(Transport->IsClosed());
    }


} // namespace
