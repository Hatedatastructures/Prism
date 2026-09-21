/**
 * @file H2MuxStreamLifetimeTest.cpp
 * @brief sing-mux H2Mux 虚拟流生命周期契约测试
 * @details 生产崩溃证据：PrismPreview 在 H2Mux 请求后以 0xC0000005 崩溃于
 *          `Preview::Composition::SingMux::H2Stream::Close()`。
 *          根因是 `co_spawn(State->Strand, CloseOnStrand(std::move(State), ...))`
 *          的实参求值顺序未指定：GCC 自右向左求值，先把 State 置空，
 *          再对空指针取 Strand。本文件锁定两条不变量：
 *          1) `Close()` 在任何状态下都不得崩溃，且后续读返回 EOF；
 *          2) 服务端关闭会话时必须唤醒已注册流的挂起读，以 EOF 收口。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <system_error>
#include <vector>

#include <Preview/Composition/H2MuxServer.hpp>
#include <Preview/Protocols/Http2/Impl.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::Composition::SingMux::H2ServerState;
    using Preview::Composition::SingMux::H2Stream;

    struct WriteProbe final
    {
        std::atomic<int> Active{0};
        std::atomic<int> Maximum{0};
    };

    class DelayedWriteTransmission final : public Preview::Transmission
    {
    public:
        DelayedWriteTransmission(Preview::SharedTransmission InnerValue,
                                 std::shared_ptr<WriteProbe> ProbeValue)
            : Inner_(std::move(InnerValue)), Probe_(std::move(ProbeValue))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Inner_->Executor();
        }

        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_return co_await Inner_->async_read_some(Buffer, ErrorCode);
        }

        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            const auto Current = Probe_->Active.fetch_add(1, std::memory_order_acq_rel) + 1;
            auto Maximum = Probe_->Maximum.load(std::memory_order_acquire);
            while (Maximum < Current &&
                   !Probe_->Maximum.compare_exchange_weak(
                       Maximum, Current, std::memory_order_acq_rel, std::memory_order_acquire))
            {
            }
            Net::steady_timer Delay(Executor());
            Delay.expires_after(std::chrono::milliseconds(10));
            co_await Delay.async_wait(Net::use_awaitable);
            std::error_code InnerError;
            const auto Written = co_await Inner_->async_write_some(Buffer, InnerError);
            ErrorCode = InnerError;
            Probe_->Active.fetch_sub(1, std::memory_order_acq_rel);
            co_return Written;
        }

        auto Close() -> void override { Inner_->Close(); }

        auto Cancel() -> void override { Inner_->Cancel(); }

        [[nodiscard]] auto IsOpen() const -> bool override { return Inner_->IsOpen(); }

    private:
        Preview::SharedTransmission Inner_;
        std::shared_ptr<WriteProbe> Probe_;
    };

    /// 构造仅含内存传输与 HTTP/2 会话的 H2 服务端状态
    auto MakeState(Net::io_context &Io) -> std::shared_ptr<H2ServerState>
    {
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto State = std::make_shared<H2ServerState>(
            std::make_shared<Preview::MemoryStream>(std::move(ServerRaw)));
        State->Session =
            std::make_shared<Preview::Http2::SessionImpl>(State->Strand, true);
        return State;
    }

    /// 看门狗：仅用于解除挂死；正常收尾会先取消它，Timeouted 保持 false
    struct Watchdog final
    {
        std::shared_ptr<Net::steady_timer> Timer;
        std::shared_ptr<bool> Timeouted{std::make_shared<bool>(false)};

        explicit Watchdog(Net::io_context &Io, std::chrono::milliseconds Budget)
            : Timer(std::make_shared<Net::steady_timer>(Io.get_executor()))
        {
            auto TimeoutedFlag = Timeouted;
            auto TimerValue = Timer;
            auto *IoPtr = &Io;
            Timer->expires_after(Budget);
            Timer->async_wait(
                [TimeoutedFlag, TimerValue, IoPtr](const boost::system::error_code &Error)
                {
                    if (Error == Net::error::operation_aborted)
                    {
                        return;
                    }
                    *TimeoutedFlag = true;
                    IoPtr->stop();
                });
        }

        auto Cancel() const -> void
        {
            Timer->cancel();
        }
    };

    TEST(H2MuxStreamLifetime, CloseThenReadReturnsEofWithoutCrash)
    {
        Net::io_context Io;
        auto State = MakeState(Io);
        bool Completed = false;
        std::size_t ReadBytes = 999;
        std::error_code ReadError = std::make_error_code(std::errc::io_error);
        Watchdog Guard(Io, std::chrono::seconds(3));

        Net::co_spawn(
            Io,
            [State, &Completed, &ReadBytes, &ReadError, Guard, &Io]()
                -> Net::awaitable<void>
            {
                auto Stream = std::make_shared<H2Stream>(State, 3);
                Stream->Close();
                for (int Index = 0; Index < 4; ++Index)
                {
                    co_await Net::post(State->Strand, Net::use_awaitable);
                }
                std::array<std::byte, 16> Buffer{};
                ReadBytes = co_await Stream->async_read_some(
                    std::span<std::byte>(Buffer), ReadError);
                Completed = true;
                Guard.Cancel();
                Io.stop();
            },
            Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(Completed);
        EXPECT_EQ(ReadBytes, 0U);
        EXPECT_FALSE(ReadError);
    }

    TEST(H2MuxStreamLifetime, ShutdownKeepsSharedTransportWritable)
    {
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(ServerRaw));
        auto State = std::make_shared<H2ServerState>(ServerTransport);
        State->Session =
            std::make_shared<Preview::Http2::SessionImpl>(State->Strand, true);
        auto Stream = std::make_shared<H2Stream>(State, 3);
        std::size_t Written = 0;
        std::error_code WriteError = std::make_error_code(std::errc::io_error);

        Net::co_spawn(
            Io,
            [Stream, ServerTransport, State, &Written, &WriteError, &Io]()
                -> Net::awaitable<void>
            {
                Stream->Shutdown();
                co_await Net::post(State->Strand, Net::use_awaitable);
                const std::array<std::byte, 4> Payload{
                    std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
                Written = co_await ServerTransport->async_write_some(Payload, WriteError);
                Io.stop();
            },
            Net::detached);

        Io.run();

        EXPECT_FALSE(WriteError);
        EXPECT_EQ(Written, 4U);
    }

    TEST(H2MuxStreamLifetime, ConcurrentStreamWritesStayFramed)
    {
        // 生产证据：Trojan + H2Mux 在 8 路并发下出现 502/超时，
        // 而顺序请求全部成功。根因是 H2ServerState::Flush() 可被多个
        // H2Stream 并发调用，WriteAll 挂起时帧会交错写入底层传输。
        // 本测试让 4 条流并发写，断言对端读到的字节流始终是完整、
        // 可解析的 HTTP/2 帧序列。
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto Probe = std::make_shared<WriteProbe>();
        auto ServerTransport = std::make_shared<DelayedWriteTransmission>(
            std::make_shared<Preview::MemoryStream>(std::move(ServerRaw)), Probe);
        auto Server = std::make_shared<Preview::Composition::SingMux::H2Server>(
            ServerTransport);
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        constexpr std::size_t StreamCount = 4;
        std::size_t Accepted = 0;
        std::size_t WritesCompleted = 0;
        std::size_t FramesParsed = 0;
        bool FeedFailed = false;
        Watchdog Guard(Io, std::chrono::seconds(5));

        Net::co_spawn(Io, Server->RunLoop(), Net::detached);
        Net::co_spawn(
            Io,
            [Server, ClientTransport, &Accepted, &WritesCompleted, &FramesParsed, &FeedFailed,
             Guard, &Io]() -> Net::awaitable<void>
            {
                auto Client = std::make_shared<Preview::Http2::SessionImpl>(
                    ClientTransport->Executor(), false);
                Client->SendSettings();
                for (std::size_t Index = 0; Index < StreamCount; ++Index)
                {
                    (void)Client->OpenStream(
                        Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
                }
                std::vector<std::byte> Wire;
                if (!Client->Collect(Wire))
                {
                    co_return;
                }
                std::error_code WriteError;
                (void)co_await ClientTransport->async_write_some(
                    std::span<const std::byte>(Wire), WriteError);

                // 并发接受并写入全部流
                std::vector<Preview::SharedTransmission> Streams;
                for (std::size_t Index = 0; Index < StreamCount; ++Index)
                {
                    auto Stream = co_await Server->AcceptStream();
                    if (!Stream)
                    {
                        break;
                    }
                    Streams.push_back(std::move(Stream));
                }
                Accepted = Streams.size();
                if (Accepted != StreamCount)
                {
                    Guard.Cancel();
                    Io.stop();
                    co_return;
                }

                std::array<std::byte, 32> Payload{};
                for (std::size_t Index = 0; Index < Payload.size(); ++Index)
                {
                    Payload[Index] = static_cast<std::byte>(Index);
                }
                for (const auto &Stream : Streams)
                {
                    Net::co_spawn(
                        Stream->Executor(),
                        [Stream, Payload, &WritesCompleted]() -> Net::awaitable<void>
                        {
                            std::error_code ErrorCode;
                            const auto Written = co_await Stream->async_write_some(
                                std::span<const std::byte>(Payload), ErrorCode);
                            if (!ErrorCode && Written == Payload.size())
                            {
                                ++WritesCompleted;
                            }
                        },
                        Net::detached);
                }

                // 收集服务端写出的字节并逐帧解析，验证无交错损坏
                std::vector<std::byte> Received;
                Net::steady_timer Settle(ClientTransport->Executor());
                Settle.expires_after(std::chrono::milliseconds(150));
                co_await Settle.async_wait(Net::use_awaitable);
                while (true)
                {
                    std::array<std::byte, 4096> Buffer{};
                    std::error_code ReadError;
                    ClientTransport->SetTimeout(std::chrono::milliseconds(20));
                    const auto Count = co_await ClientTransport->async_read_some(
                        std::span<std::byte>(Buffer), ReadError);
                    if (Count == 0 || ReadError)
                    {
                        break;
                    }
                    Received.insert(Received.end(), Buffer.begin(),
                                    Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
                }
                ClientTransport->SetTimeout(std::chrono::milliseconds(0));

                // 直接用帧头逐帧校验：每帧必须是长度自洽的完整 HTTP/2 帧。
                // 交错损坏会让长度字段跨越到别的流的载荷，从而解析越界。
                std::size_t Offset = 0;
                std::size_t FrameCount = 0;
                while (Offset + 9U <= Received.size())
                {
                    const auto Length =
                        (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Received[Offset]))
                         << 16U) |
                        (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Received[Offset + 1]))
                         << 8U) |
                        static_cast<std::size_t>(std::to_integer<std::uint8_t>(Received[Offset + 2]));
                    if (Length > 16384U || Offset + 9U + Length > Received.size())
                    {
                        FeedFailed = true;
                        break;
                    }
                    Offset += 9U + Length;
                    ++FrameCount;
                }
                if (Offset != Received.size())
                {
                    FeedFailed = true;
                }
                FramesParsed = FrameCount;
                FramesParsed = Received.size();
                Guard.Cancel();
                Io.stop();
            },
            Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_EQ(Accepted, StreamCount);
        EXPECT_EQ(WritesCompleted, StreamCount);
        EXPECT_FALSE(FeedFailed);
        EXPECT_GT(FramesParsed, 0U);
        EXPECT_EQ(Probe->Maximum.load(std::memory_order_acquire), 1);
    }

    TEST(H2MuxStreamLifetime, ConcurrentStreamWritesAndCloseKeepSiblingStreamsUsable)
    {
        // 真实 Mihomo H2Mux 失败形状：多条流同时收到上游响应时，某条流在
        // 关闭路径占用共享 writer，兄弟流的响应写回被拖到客户端超时。
        // 这里同时写入并关闭四条虚拟流，要求每条流都完成自己的响应和 FIN。
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto Probe = std::make_shared<WriteProbe>();
        auto ServerTransport = std::make_shared<DelayedWriteTransmission>(
            std::make_shared<Preview::MemoryStream>(std::move(ServerRaw)), Probe);
        auto Server = std::make_shared<Preview::Composition::SingMux::H2Server>(
            ServerTransport);
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        constexpr std::size_t StreamCount = 4;
        std::size_t Accepted = 0;
        std::size_t WritesCompleted = 0;
        std::size_t ClosesIssued = 0;
        Watchdog Guard(Io, std::chrono::seconds(5));

        Net::co_spawn(Io, Server->RunLoop(), Net::detached);
        Net::co_spawn(
            Io,
            [Server, ClientTransport, &Accepted, &WritesCompleted, &ClosesIssued, Guard,
             &Io]() -> Net::awaitable<void>
            {
                auto Client = std::make_shared<Preview::Http2::SessionImpl>(
                    ClientTransport->Executor(), false);
                Client->SendSettings();
                for (std::size_t Index = 0; Index < StreamCount; ++Index)
                {
                    (void)Client->OpenStream(
                        Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
                }
                std::vector<std::byte> Wire;
                if (!Client->Collect(Wire))
                {
                    co_return;
                }
                std::error_code WriteError;
                (void)co_await ClientTransport->async_write_some(
                    std::span<const std::byte>(Wire), WriteError);

                std::vector<Preview::SharedTransmission> Streams;
                for (std::size_t Index = 0; Index < StreamCount; ++Index)
                {
                    auto Stream = co_await Server->AcceptStream();
                    if (!Stream)
                    {
                        break;
                    }
                    Streams.push_back(std::move(Stream));
                }
                Accepted = Streams.size();
                if (Accepted != StreamCount)
                {
                    Guard.Cancel();
                    Io.stop();
                    co_return;
                }

                const std::array<std::byte, 32> Payload{};
                for (const auto &Stream : Streams)
                {
                    Net::co_spawn(
                        Stream->Executor(),
                        [Stream, Payload, &WritesCompleted, &ClosesIssued]()
                            -> Net::awaitable<void>
                        {
                            std::error_code ErrorCode;
                            const auto Written = co_await Stream->async_write_some(
                                std::span<const std::byte>(Payload), ErrorCode);
                            if (!ErrorCode && Written == Payload.size())
                            {
                                ++WritesCompleted;
                            }
                            Stream->Close();
                            ++ClosesIssued;
                        },
                        Net::detached);
                }

                Net::steady_timer Settle(ClientTransport->Executor());
                Settle.expires_after(std::chrono::milliseconds(400));
                co_await Settle.async_wait(Net::use_awaitable);
                Guard.Cancel();
                Io.stop();
            },
            Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_EQ(Accepted, StreamCount);
        EXPECT_EQ(WritesCompleted, StreamCount);
        EXPECT_EQ(ClosesIssued, StreamCount);
        EXPECT_EQ(Probe->Maximum.load(std::memory_order_acquire), 1);
    }

    TEST(H2MuxStreamLifetime, CancelingOneStreamKeepsSiblingStreamsUsable)
    {
        // 生产证据：Trojan + H2Mux 并发下间歇失败（多轮 2/8~7/8），
        // 诊断显示 accept-wait 次数远多于 accepted，且一次 stream-request
        // 失败后整条会话再无流被接受。
        // 根因：H2Stream::Cancel() 调用 State_->Raw->Cancel()，而 Raw 是
        // 整个会话共享的底层传输；取消单条流会连带取消所有兄弟流。
        // 本测试取消一条流后，断言兄弟流仍可正常读写。
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto Server = std::make_shared<Preview::Composition::SingMux::H2Server>(
            std::make_shared<Preview::MemoryStream>(std::move(ServerRaw)));
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        constexpr std::size_t StreamCount = 3;
        std::size_t Accepted = 0;
        std::size_t SiblingWrites = 0;
        Watchdog Guard(Io, std::chrono::seconds(3));

        Net::co_spawn(Io, Server->RunLoop(), Net::detached);
        Net::co_spawn(
            Io,
            [Server, ClientTransport, &Accepted, &SiblingWrites, Guard, &Io]()
                -> Net::awaitable<void>
            {
                auto Client = std::make_shared<Preview::Http2::SessionImpl>(
                    ClientTransport->Executor(), false);
                Client->SendSettings();
                for (std::size_t Index = 0; Index < StreamCount; ++Index)
                {
                    (void)Client->OpenStream(
                        Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
                }
                std::vector<std::byte> Wire;
                if (!Client->Collect(Wire))
                {
                    co_return;
                }
                std::error_code WriteError;
                (void)co_await ClientTransport->async_write_some(
                    std::span<const std::byte>(Wire), WriteError);

                std::vector<Preview::SharedTransmission> Streams;
                for (std::size_t Index = 0; Index < StreamCount; ++Index)
                {
                    auto Stream = co_await Server->AcceptStream();
                    if (!Stream)
                    {
                        break;
                    }
                    Streams.push_back(std::move(Stream));
                }
                Accepted = Streams.size();
                if (Accepted < 2)
                {
                    Guard.Cancel();
                    Io.stop();
                    co_return;
                }

                // 取消第一条流（模拟单流失败/客户端放弃）
                Streams[0]->Cancel();
                Streams[0]->Close();
                for (int Index = 0; Index < 4; ++Index)
                {
                    co_await Net::post(Streams[1]->Executor(), Net::use_awaitable);
                }

                // 兄弟流必须仍然可写
                std::array<std::byte, 16> Payload{};
                for (std::size_t Index = 1; Index < Streams.size(); ++Index)
                {
                    std::error_code ErrorCode;
                    const auto Written = co_await Streams[Index]->async_write_some(
                        std::span<const std::byte>(Payload), ErrorCode);
                    if (!ErrorCode && Written == Payload.size())
                    {
                        ++SiblingWrites;
                    }
                }
                Guard.Cancel();
                Io.stop();
            },
            Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_EQ(Accepted, StreamCount);
        EXPECT_EQ(SiblingWrites, StreamCount - 1);
    }

    TEST(H2MuxStreamLifetime, AcceptStreamDeliversAllQueuedStreamsWithoutLoss)
    {
        // 生产证据：Trojan + H2Mux 在 8 路并发下间歇失败（5 轮中 2 轮失败，
        // 最差 2/8），失败会话在 Stage=mux started 后卡满客户端 10s 超时。
        // 根因：AcceptStream 用 Notify.reset() + async_receive 等待，
        // 而 OnHeaders 对每个新流只 try_send 一次；通道容量为 1 时
        // 并发入队的信号会丢失，导致已排队的流无人唤醒。
        // 本测试一次性注入 4 条流，断言全部可被 AcceptStream 取出。
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto Server = std::make_shared<Preview::Composition::SingMux::H2Server>(
            std::make_shared<Preview::MemoryStream>(std::move(ServerRaw)));
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        constexpr std::size_t StreamCount = 4;
        std::size_t Accepted = 0;
        Watchdog Guard(Io, std::chrono::seconds(3));

        Net::co_spawn(Io, Server->RunLoop(), Net::detached);
        Net::co_spawn(
            Io,
            [Server, ClientTransport, &Accepted, Guard, &Io]() -> Net::awaitable<void>
            {
                auto Client = std::make_shared<Preview::Http2::SessionImpl>(
                    ClientTransport->Executor(), false);
                Client->SendSettings();
                for (std::size_t Index = 0; Index < StreamCount; ++Index)
                {
                    (void)Client->OpenStream(
                        Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
                }
                std::vector<std::byte> Wire;
                if (!Client->Collect(Wire))
                {
                    co_return;
                }
                std::error_code WriteError;
                (void)co_await ClientTransport->async_write_some(
                    std::span<const std::byte>(Wire), WriteError);

                for (std::size_t Index = 0; Index < StreamCount; ++Index)
                {
                    auto Stream = co_await Server->AcceptStream();
                    if (!Stream)
                    {
                        break;
                    }
                    ++Accepted;
                }
                Guard.Cancel();
                Io.stop();
            },
            Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_EQ(Accepted, StreamCount);
    }

    TEST(H2MuxStreamLifetime, ServerCloseWakesPendingStreamReadWithEof)
    {
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto Server = std::make_shared<Preview::Composition::SingMux::H2Server>(
            std::make_shared<Preview::MemoryStream>(std::move(ServerRaw)));
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        bool Accepted = false;
        bool Completed = false;
        std::size_t ReadBytes = 999;
        std::error_code ReadError = std::make_error_code(std::errc::io_error);
        Watchdog Guard(Io, std::chrono::seconds(3));

        Net::co_spawn(Io, Server->RunLoop(), Net::detached);
        Net::co_spawn(
            Io,
            [Server, ClientTransport, &Accepted, &Completed, &ReadBytes, &ReadError, Guard,
             &Io]() -> Net::awaitable<void>
            {
                // 真实客户端路径：SETTINGS + CONNECT 流 → 服务端 AcceptStream
                auto Client = std::make_shared<Preview::Http2::SessionImpl>(
                    ClientTransport->Executor(), false);
                Client->SendSettings();
                const auto ClientStreamId = Client->OpenStream(
                    Preview::Http2::HeaderList{{":method", "CONNECT"}}, false);
                EXPECT_GT(ClientStreamId, 0);
                std::vector<std::byte> Wire;
                EXPECT_TRUE(Client->Collect(Wire));
                std::error_code WriteError;
                (void)co_await ClientTransport->async_write_some(
                    std::span<const std::byte>(Wire), WriteError);
                EXPECT_FALSE(WriteError);

                auto Stream = co_await Server->AcceptStream();
                EXPECT_TRUE(Stream);
                Accepted = static_cast<bool>(Stream);
                if (!Stream)
                {
                    Completed = true;
                    co_return;
                }

                Net::co_spawn(
                    Stream->Executor(),
                    [Stream, &Completed, &ReadBytes, &ReadError]()
                        -> Net::awaitable<void>
                    {
                        std::array<std::byte, 16> Buffer{};
                        ReadBytes = co_await Stream->async_read_some(
                            std::span<std::byte>(Buffer), ReadError);
                        Completed = true;
                    },
                    Net::detached);
                // 让挂起读进入 channel 等待，再关闭服务端
                for (int Index = 0; Index < 4; ++Index)
                {
                    co_await Net::post(Stream->Executor(), Net::use_awaitable);
                }
                Server->Close();
                Net::steady_timer Settle(Stream->Executor());
                Settle.expires_after(std::chrono::milliseconds(50));
                co_await Settle.async_wait(Net::use_awaitable);
                Guard.Cancel();
                Io.stop();
            },
            Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(Accepted);
        EXPECT_TRUE(Completed);
        EXPECT_EQ(ReadBytes, 0U);
        EXPECT_FALSE(ReadError);
    }

} // namespace
