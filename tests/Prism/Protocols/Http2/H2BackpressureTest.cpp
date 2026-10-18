/**
 * @file H2BackpressureTest.cpp
 * @brief HTTP/2 发送窗口准入、等待和取消合同测试。
 */
#include <Prism/Protocols/Http2/Detail/Frame.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Http2/Stream.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    namespace H2 = Prism::Http2;
    namespace Net = boost::asio;

    [[nodiscard]] auto FeedPeerInitialWindow(
        H2::Session &Session,
        const std::uint32_t InitialWindow) -> bool
    {
        const std::array<H2::SettingsEntry, 1> Entries{{
            {H2::SettingsInitialWindowSize, InitialWindow}}};
        const auto Payload = H2::Detail::EncodeSettings(Entries);
        const auto Frame = H2::Detail::BuildFrame({
            H2::Detail::FrameType::Settings, H2::Detail::FlagNone, 0, Payload});
        std::error_code Error;
        return Session.Feed(Frame, Error) && !Error;
    }

    [[nodiscard]] auto FeedWindowUpdate(
        H2::Session &Session,
        const std::uint32_t StreamId,
        const std::uint32_t Increment) -> bool
    {
        const auto Payload = H2::Detail::EncodeWindowUpdate(Increment);
        const auto Frame = H2::Detail::BuildFrame({
            H2::Detail::FrameType::WindowUpdate, H2::Detail::FlagNone, StreamId, Payload});
        std::error_code Error;
        return Session.Feed(Frame, Error) && !Error;
    }

    /**
     * @brief 为背压用例创建带零初始窗口的客户端 stream。
     * @param IoContext 提供 Session executor 的测试上下文。
     * @return 成功返回由测试持有的 Session 和 stream ID；失败保留 stream-open Failure，
     *         或在构造测试窗口帧失败时返回 ProtocolError。
     * @details 同步测试装配没有取消点；IoContext/fixture 负责驱动和销毁 Session。
     */
    [[nodiscard]] auto MakeBlockedClient(
        Net::io_context &IoContext)
        -> std::expected<std::pair<std::shared_ptr<H2::Session>, std::int32_t>,
                         Prism::Fault::Failure>
    {
        auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        const auto Opened = Session->OpenStream({{":method", "POST"}}, false);
        if (!Opened)
        {
            return std::unexpected(Opened.error());
        }
        if (!FeedPeerInitialWindow(*Session, 0))
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
        }
        return std::pair{std::move(Session), *Opened};
    }

    TEST(H2Backpressure, PublicStreamErrorsAndHandlesUseValidDomainStates)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        auto Server = std::make_shared<H2::Session>(IoContext.get_executor(), true);

        const auto ServerOpen = Server->OpenStream({}, false);
        ASSERT_FALSE(ServerOpen);
        EXPECT_EQ(ServerOpen.error().Code, Prism::Fault::Code::NotSupported);

        const auto MissingSession = H2::OpenStreamHandle({}, {}, false);
        ASSERT_FALSE(MissingSession);
        EXPECT_EQ(MissingSession.error().Code, Prism::Fault::Code::InvalidArgument);

        H2::StreamHandle InvalidHandle(0, Client);
        EXPECT_FALSE(InvalidHandle.IsOpen());

        const auto ClientOpen = Client->OpenStream({}, false);
        ASSERT_TRUE(ClientOpen);
        H2::StreamHandle ValidHandle(*ClientOpen, Client);
        EXPECT_TRUE(ValidHandle.IsOpen());
    }

    auto StreamWindowUpdateScenario(Net::io_context &IoContext, bool &Completed)
        -> Net::awaitable<void>
    {
        auto Prepared = MakeBlockedClient(IoContext);
        if (!Prepared)
        {
            ADD_FAILURE() << "failed to create zero-window stream";
            co_return;
        }
        auto [Session, StreamId] = std::move(*Prepared);
        Net::steady_timer Update(IoContext);
        Update.expires_after(std::chrono::milliseconds(1));
        Update.async_wait([Session, StreamId](const boost::system::error_code &Error)
        {
            if (!Error) EXPECT_TRUE(FeedWindowUpdate(*Session, StreamId, 1));
        });

        const auto Ready = co_await Session->AwaitWritable(StreamId, 1);
        if (!Ready)
        {
            ADD_FAILURE() << "stream update did not wake waiter";
            co_return;
        }
        const std::array<std::byte, 1> Payload{std::byte{0x41}};
        EXPECT_EQ(Session->SubmitData(StreamId, Payload, false), H2::SubmitDataStatus::Accepted);
        Completed = true;
    }

    auto ConnectionWindowUpdateScenario(Net::io_context &IoContext, bool &Completed)
        -> Net::awaitable<void>
    {
        auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        const auto OpenedFullStream = Session->OpenStream({}, false);
        const auto OpenedWaitingStream = Session->OpenStream({}, false);
        if (!OpenedFullStream || !OpenedWaitingStream)
        {
            ADD_FAILURE() << "failed to open connection-window streams";
            co_return;
        }
        const auto FullStream = *OpenedFullStream;
        const auto WaitingStream = *OpenedWaitingStream;
        const std::vector<std::byte> FullWindow(65535, std::byte{0x6B});
        if (Session->SubmitData(FullStream, FullWindow, false) != H2::SubmitDataStatus::Accepted)
        {
            ADD_FAILURE() << "default connection window was not accepted";
            co_return;
        }
        const std::array<std::byte, 1> Payload{std::byte{0x42}};
        EXPECT_EQ(Session->SubmitData(WaitingStream, Payload, false), H2::SubmitDataStatus::Blocked);

        Net::steady_timer Update(IoContext);
        Update.expires_after(std::chrono::milliseconds(1));
        Update.async_wait([Session](const boost::system::error_code &Error)
        {
            if (!Error) EXPECT_TRUE(FeedWindowUpdate(*Session, 0, 1));
        });
        const auto Ready = co_await Session->AwaitWritable(WaitingStream, Payload.size());
        if (!Ready)
        {
            ADD_FAILURE() << "connection update did not wake waiter";
            co_return;
        }
        EXPECT_EQ(Session->SubmitData(WaitingStream, Payload, false), H2::SubmitDataStatus::Accepted);
        Completed = true;
    }

    auto InitialWindowSettingsScenario(Net::io_context &IoContext, bool &Completed)
        -> Net::awaitable<void>
    {
        auto Prepared = MakeBlockedClient(IoContext);
        if (!Prepared)
        {
            ADD_FAILURE() << "failed to create zero-window stream";
            co_return;
        }
        auto [Session, StreamId] = std::move(*Prepared);
        Net::steady_timer Update(IoContext);
        Update.expires_after(std::chrono::milliseconds(1));
        Update.async_wait([Session](const boost::system::error_code &Error)
        {
            if (!Error) EXPECT_TRUE(FeedPeerInitialWindow(*Session, 1));
        });
        const auto Ready = co_await Session->AwaitWritable(StreamId, 1);
        if (!Ready)
        {
            ADD_FAILURE() << "initial-window setting did not wake waiter";
            co_return;
        }
        Completed = true;
    }

    auto FeedRemoteReset(const std::shared_ptr<H2::Session> &Session, const std::int32_t StreamId) -> void
    {
        const auto Payload = H2::Detail::EncodeRstStream(H2::ErrorCancel);
        const auto Frame = H2::Detail::BuildFrame({
            H2::Detail::FrameType::RstStream, H2::Detail::FlagNone,
            static_cast<std::uint32_t>(StreamId), Payload});
        std::error_code FeedError;
        EXPECT_TRUE(Session->Feed(Frame, FeedError));
        EXPECT_FALSE(FeedError);
    }

    struct RemoteResetFeed final
    {
        std::shared_ptr<H2::Session> Session;
        std::int32_t StreamId{0};

        auto operator()(const boost::system::error_code &Error) const -> void
        {
            if (!Error) FeedRemoteReset(Session, StreamId);
        }
    };

    auto RemoteResetScenario(Net::io_context &IoContext, bool &Completed)
        -> Net::awaitable<void>
    {
        auto Prepared = MakeBlockedClient(IoContext);
        if (!Prepared)
        {
            ADD_FAILURE() << "failed to create zero-window stream";
            co_return;
        }
        auto [Session, StreamId] = std::move(*Prepared);
        Net::steady_timer Reset(IoContext);
        Reset.expires_after(std::chrono::milliseconds(1));
        Reset.async_wait(RemoteResetFeed{Session, StreamId});
        const auto Ready = co_await Session->AwaitWritable(StreamId, 1);
        if (Ready)
        {
            ADD_FAILURE() << "reset did not close writable wait";
            co_return;
        }
        EXPECT_EQ(Ready.error().Code, Prism::Fault::Code::ConnectionAborted);
        const std::array<std::byte, 1> Payload{std::byte{0x44}};
        EXPECT_EQ(Session->SubmitData(StreamId, Payload, false), H2::SubmitDataStatus::Closed);
        Completed = true;
    }

    auto LocalResetScenario(Net::io_context &IoContext, bool &Completed)
        -> Net::awaitable<void>
    {
        auto Prepared = MakeBlockedClient(IoContext);
        if (!Prepared)
        {
            ADD_FAILURE() << "failed to create zero-window stream";
            co_return;
        }
        auto [Session, StreamId] = std::move(*Prepared);
        Net::steady_timer Reset(IoContext);
        Reset.expires_after(std::chrono::milliseconds(1));
        Reset.async_wait([Session, StreamId](const boost::system::error_code &Error)
        {
            if (!Error) EXPECT_TRUE(Session->ResetStream(StreamId, H2::ErrorCancel));
        });
        const auto Ready = co_await Session->AwaitWritable(StreamId, 1);
        if (Ready)
        {
            ADD_FAILURE() << "local reset did not close writable wait";
            co_return;
        }
        EXPECT_EQ(Ready.error().Code, Prism::Fault::Code::ConnectionAborted);
        Completed = true;
    }

    auto LocalFinScenario(Net::io_context &IoContext, bool &Completed)
        -> Net::awaitable<void>
    {
        auto Prepared = MakeBlockedClient(IoContext);
        if (!Prepared)
        {
            ADD_FAILURE() << "failed to create zero-window stream";
            co_return;
        }
        auto [Session, StreamId] = std::move(*Prepared);
        Net::steady_timer Finish(IoContext);
        Finish.expires_after(std::chrono::milliseconds(1));
        Finish.async_wait([Session, StreamId](const boost::system::error_code &Error)
        {
            if (!Error)
                EXPECT_EQ(Session->SubmitData(StreamId, {}, true), H2::SubmitDataStatus::Accepted);
        });
        const auto Ready = co_await Session->AwaitWritable(StreamId, 1);
        if (Ready)
        {
            ADD_FAILURE() << "local FIN did not close writable wait";
            co_return;
        }
        EXPECT_EQ(Ready.error().Code, Prism::Fault::Code::ConnectionAborted);
        Completed = true;
    }

    TEST(H2Backpressure, BlockedSubmissionKeepsCallerBufferAndQueuesNoData)
    {
        Net::io_context IoContext;
        auto Prepared = MakeBlockedClient(IoContext);
        ASSERT_TRUE(Prepared);
        auto [Session, StreamId] = std::move(*Prepared);
        ASSERT_GT(StreamId, 0);
        const std::vector<std::byte> Payload(17, std::byte{0x5A});
        const auto Original = Payload;

        EXPECT_EQ(Session->SubmitData(StreamId, Payload, false), H2::SubmitDataStatus::Blocked);
        EXPECT_EQ(Payload, Original);

        std::vector<std::byte> Output;
        ASSERT_TRUE(Session->Collect(Output));
        constexpr std::string_view ClientPreface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        const auto PrefaceWire = std::as_bytes(std::span(ClientPreface));
        ASSERT_GE(Output.size(), PrefaceWire.size());
        ASSERT_TRUE(std::equal(PrefaceWire.begin(), PrefaceWire.end(), Output.begin()));
        std::size_t Offset = PrefaceWire.size();
        while (Offset < Output.size())
        {
            const auto Remaining = std::span<const std::byte>(Output).subspan(Offset);
            const auto Header = H2::Detail::ParseFrameHeader(Remaining);
            ASSERT_TRUE(Header.has_value());
            ASSERT_LE(H2::Detail::FrameHeaderSize + Header->Length, Remaining.size());
            EXPECT_NE(Header->Type, H2::Detail::FrameType::Data);
            Offset += H2::Detail::FrameHeaderSize + Header->Length;
        }
    }

    TEST(H2Backpressure, EmptyEndStreamIsNotBlockedByNegativeStreamWindow)
    {
        Net::io_context IoContext;
        H2::Session Session(IoContext.get_executor(), false);
        const auto Opened = Session.OpenStream({}, false);
        ASSERT_TRUE(Opened);
        const auto StreamId = *Opened;
        ASSERT_GT(StreamId, 0);
        const std::array<std::byte, 1> Payload{std::byte{0x5A}};
        ASSERT_EQ(Session.SubmitData(StreamId, Payload, false), H2::SubmitDataStatus::Accepted);
        ASSERT_TRUE(FeedPeerInitialWindow(Session, 0));

        EXPECT_EQ(Session.SubmitData(StreamId, {}, true), H2::SubmitDataStatus::Accepted);
        std::vector<std::byte> Output;
        ASSERT_TRUE(Session.Collect(Output));
        bool EndStreamFound = false;
        constexpr std::string_view ClientPreface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        const auto PrefaceWire = std::as_bytes(std::span(ClientPreface));
        ASSERT_GE(Output.size(), PrefaceWire.size());
        ASSERT_TRUE(std::equal(PrefaceWire.begin(), PrefaceWire.end(), Output.begin()));
        std::size_t Offset = PrefaceWire.size();
        while (Offset < Output.size())
        {
            const auto Remaining = std::span<const std::byte>(Output).subspan(Offset);
            const auto Header = H2::Detail::ParseFrameHeader(Remaining);
            ASSERT_TRUE(Header.has_value());
            ASSERT_LE(H2::Detail::FrameHeaderSize + Header->Length, Remaining.size());
            if (Header->Type == H2::Detail::FrameType::Data &&
                (Header->Flags & H2::Detail::FlagEndStream) != 0)
            {
                EndStreamFound = true;
            }
            Offset += H2::Detail::FrameHeaderSize + Header->Length;
        }
        EXPECT_TRUE(EndStreamFound);
    }

    TEST(H2Backpressure, AwaitWritableWakesOnStreamWindowUpdate)
    {
        Net::io_context IoContext;
        bool Completed = false;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, StreamWindowUpdateScenario(IoContext, Completed),
            [&Exception](std::exception_ptr Value)
        {
            Exception = std::move(Value);
        });
        IoContext.run();
        EXPECT_FALSE(Exception);
        EXPECT_TRUE(Completed);
    }

    TEST(H2Backpressure, AwaitWritableWakesOnConnectionWindowUpdate)
    {
        Net::io_context IoContext;
        bool Completed = false;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, ConnectionWindowUpdateScenario(IoContext, Completed),
            [&Exception](std::exception_ptr Value)
        {
            Exception = std::move(Value);
        });
        IoContext.run();
        EXPECT_FALSE(Exception);
        EXPECT_TRUE(Completed);
    }

    TEST(H2Backpressure, AwaitWritableWakesOnInitialWindowSettings)
    {
        Net::io_context IoContext;
        bool Completed = false;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, InitialWindowSettingsScenario(IoContext, Completed),
            [&Exception](std::exception_ptr Value)
        {
            Exception = std::move(Value);
        });
        IoContext.run();
        EXPECT_FALSE(Exception);
        EXPECT_TRUE(Completed);
    }

    TEST(H2Backpressure, AwaitWritableCancellationPreservesBlockedData)
    {
        Net::io_context IoContext;
        auto Prepared = MakeBlockedClient(IoContext);
        ASSERT_TRUE(Prepared);
        auto [Session, StreamId] = std::move(*Prepared);
        ASSERT_GT(StreamId, 0);
        const std::array<std::byte, 1> Payload{std::byte{0x43}};
        ASSERT_EQ(Session->SubmitData(StreamId, Payload, false), H2::SubmitDataStatus::Blocked);

        Net::cancellation_signal Cancellation;
        Net::steady_timer Trigger(IoContext);
        Trigger.expires_after(std::chrono::milliseconds(1));
        Trigger.async_wait([&Cancellation](const boost::system::error_code &Error)
        {
            if (!Error)
            {
                Cancellation.emit(Net::cancellation_type::all);
            }
        });
        std::optional<std::expected<void, Prism::Fault::Failure>> Result;
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            Session->AwaitWritable(StreamId, Payload.size()),
            Net::bind_cancellation_slot(
                Cancellation.slot(),
                [&Result, &Exception](std::exception_ptr Value,
                    std::expected<void, Prism::Fault::Failure> Outcome)
                {
                    Exception = std::move(Value);
                    if (!Exception)
                    {
                        Result.emplace(std::move(Outcome));
                    }
                }));
        IoContext.run();

        EXPECT_FALSE(Exception);
        ASSERT_TRUE(Result.has_value());
        ASSERT_FALSE(Result->has_value());
        EXPECT_EQ(Result->error().Code, Prism::Fault::Code::Canceled);
        EXPECT_EQ(Session->SubmitData(StreamId, Payload, false), H2::SubmitDataStatus::Blocked);
    }

    TEST(H2Backpressure, ResetWakesWaiterAsClosed)
    {
        Net::io_context IoContext;
        bool Completed = false;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, RemoteResetScenario(IoContext, Completed),
            [&Exception](std::exception_ptr Value)
        {
            Exception = std::move(Value);
        });
        IoContext.run();
        EXPECT_FALSE(Exception);
        EXPECT_TRUE(Completed);
    }

    TEST(H2Backpressure, LocalResetWakesWaiterAsClosed)
    {
        Net::io_context IoContext;
        bool Completed = false;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, LocalResetScenario(IoContext, Completed),
            [&Exception](std::exception_ptr Value)
        {
            Exception = std::move(Value);
        });
        IoContext.run();
        EXPECT_FALSE(Exception);
        EXPECT_TRUE(Completed);
    }

    TEST(H2Backpressure, LocalFinWakesWaiterAsClosed)
    {
        Net::io_context IoContext;
        bool Completed = false;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, LocalFinScenario(IoContext, Completed),
            [&Exception](std::exception_ptr Value)
        {
            Exception = std::move(Value);
        });
        IoContext.run();
        EXPECT_FALSE(Exception);
        EXPECT_TRUE(Completed);
    }
}
