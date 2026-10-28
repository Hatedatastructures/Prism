/**
 * @file StreamTest.cpp
 * @brief MemoryStream 生命周期、超时和传输接口行为测试。
 * @details 保留双端数据、关闭、取消、半关闭、超时及泛型传输契约场景。
 */

#include "../Core/Resources.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <utility>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using ReadCompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief 驱动单个协程至完成，真实协程异常仍由测试线程观察。 */
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

    /** @brief 写入原始消息并从配对端完整观察同一字节序列。 */
    auto RunMemoryPairEcho(Prism::MemoryStream &Source, Prism::MemoryStream &Destination)
        -> Net::awaitable<void>
    {
        const std::string Message = "hello memory pipe";
        const auto WriteResult = co_await Source.WriteExact(std::as_bytes(std::span(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Message.data()), Message.size()))));
        EXPECT_TRUE(WriteResult.Failure.Succeeded());
        std::array<std::uint8_t, 64> Buffer{};
        const auto ReadResult = co_await Destination.ReadSome(std::as_writable_bytes(std::span(Buffer)));
        EXPECT_EQ(ReadResult.Bytes, Message.size());
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), ReadResult.Bytes), Message);
    }

    /** @brief 保留 MemoryStream 完整关闭后的对端 EOF 与写入错误断言。 */
    auto RunMemoryPairCloseSemantics(Prism::MemoryStream &Source, Prism::MemoryStream &Destination)
        -> Net::awaitable<void>
    {
        const auto CloseResult = Source.Close();
        std::array<std::uint8_t, 8> Buffer{};
        const auto ReadResult = co_await Destination.ReadSome(std::as_writable_bytes(std::span(Buffer)));
        EXPECT_EQ(ReadResult.Bytes, 0U);
        const auto WriteResult = co_await Destination.WriteExact(std::as_bytes(std::span(Buffer)));
        EXPECT_EQ(WriteResult.Failure.Code, Prism::Fault::Code::ConnectionAborted);
        const auto DrainResult = co_await Source.Activity()->Drain();
        EXPECT_TRUE(CloseResult.has_value());
        EXPECT_TRUE(DrainResult.has_value());
    }

    /** @brief 保留 50 毫秒读取上限和至少 40 毫秒的真实耗时门槛。 */
    auto RunReadTimeout(Prism::MemoryStream &Source, bool &TimedOut) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 16> Buffer{};
        Source.SetTimeout(std::chrono::milliseconds(50));
        const auto Started = std::chrono::steady_clock::now();
        const auto Result = co_await Source.ReadSome(std::as_writable_bytes(std::span(Buffer)));
        const auto Elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - Started)
                                 .count();
        EXPECT_EQ(Result.Bytes, 0U);
        EXPECT_GE(Elapsed, 40);
        TimedOut = true;
    }

    /** @brief 保留写方向半关闭及反向读取仍可用的双向断言。 */
    auto RunShutdownSemantics(Prism::MemoryStream &Source, Prism::MemoryStream &Destination)
        -> Net::awaitable<void>
    {
        const auto ShutdownResult = co_await Source.WriteShutdown();
        EXPECT_TRUE(ShutdownResult.has_value());
        std::array<std::uint8_t, 8> Buffer{};
        const auto ReadResult = co_await Destination.ReadSome(std::as_writable_bytes(std::span(Buffer)));
        EXPECT_EQ(ReadResult.Bytes, 0U);
        const auto LocalWrite = co_await Source.WriteExact(std::as_bytes(std::span(Buffer)));
        EXPECT_EQ(LocalWrite.Failure.Code, Prism::Fault::Code::ConnectionAborted);
        const auto ReplyWrite = co_await Destination.WriteExact(std::as_bytes(std::span(Buffer)));
        EXPECT_TRUE(ReplyWrite.Failure.Succeeded());
        std::array<std::uint8_t, 8> Reply{};
        const auto ReplyRead = co_await Source.ReadSome(std::as_writable_bytes(std::span(Reply)));
        EXPECT_EQ(ReplyRead.Bytes, 8U);
    }

    /** @brief 等待被取消的 pending read，并保留零字节完成结果。 */
    auto RunPendingCancelRead(Prism::MemoryStream &Source) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 8> Buffer{};
        const auto Result = co_await Source.ReadSome(std::as_writable_bytes(std::span(Buffer)));
        EXPECT_EQ(Result.Bytes, 0U);
    }

    /** @brief 用同一 executor 启动、取消并等待挂起读取的 owner。 */
    auto RunCancelSemantics(Prism::MemoryStream &Source) -> Net::awaitable<void>
    {
        const auto Done = std::make_shared<ReadCompletionChannel>(Source.Executor(), 1);
        std::exception_ptr Failure;
        Net::co_spawn(Source.Executor(), RunPendingCancelRead(Source), [&Failure, Done](std::exception_ptr Error)
                      {
                          Failure = std::move(Error);
                          (void)Done->try_send(boost::system::error_code{});
                      });
        co_await Net::post(Source.Executor(), Net::use_awaitable);
        co_await Net::post(Source.Executor(), Net::use_awaitable);
        const auto CancelResult = Source.Cancel();
        co_await Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(Failure);
        const auto FinalClose = Source.Close();
        const auto DrainResult = co_await Source.Activity()->Drain();
        EXPECT_TRUE(FinalClose.has_value());
        EXPECT_TRUE(CancelResult.has_value());
        EXPECT_TRUE(DrainResult.has_value());
    }

    /** @brief 读取 pending 数据并在结束时记录原来的零字节检查。 */
    auto RunMemoryPendingRead(const std::shared_ptr<Prism::MemoryStream> &Source,
                              const std::shared_ptr<bool> &ReadDone) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 8> Buffer{};
        const auto Result = co_await Source->ReadSome(std::as_writable_bytes(std::span(Buffer)));
        EXPECT_EQ(Result.Bytes, 0U);
        *ReadDone = true;
    }

    /** @brief 通过原 executor 关闭 pending-read owner 并等待子协程与稳定窗口。 */
    auto RunMemoryCloseWhilePending(const std::shared_ptr<Prism::MemoryStream> &Source,
                                    const std::shared_ptr<bool> &ReadDone,
                                    const std::shared_ptr<std::exception_ptr> &ChildException)
        -> Net::awaitable<void>
    {
        const auto Done = std::make_shared<ReadCompletionChannel>(Source->Executor(), 1);
        Net::co_spawn(Source->Executor(), RunMemoryPendingRead(Source, ReadDone),
                      [ChildException, Done](std::exception_ptr Error)
                      {
                          *ChildException = std::move(Error);
                          (void)Done->try_send(boost::system::error_code{});
                      });
        co_await Net::post(Source->Executor(), Net::use_awaitable);
        const auto CloseResult = Source->Close();
        co_await Done->async_receive(Net::use_awaitable);
        Net::steady_timer Wait(Source->Executor());
        Wait.expires_after(std::chrono::milliseconds(20));
        co_await Wait.async_wait(Net::use_awaitable);
        const auto FinalClose = Source->Close();
        const auto DrainResult = co_await Source->Activity()->Drain();
        EXPECT_TRUE(FinalClose.has_value());
        EXPECT_TRUE(CloseResult.has_value());
        EXPECT_TRUE(DrainResult.has_value());
    }

    /** @brief 通过原 executor 取消 pending-read owner 并等待子协程与稳定窗口。 */
    auto RunMemoryCancelWhilePending(const std::shared_ptr<Prism::MemoryStream> &Source,
                                     const std::shared_ptr<bool> &ReadDone,
                                     const std::shared_ptr<std::exception_ptr> &ChildException)
        -> Net::awaitable<void>
    {
        const auto Done = std::make_shared<ReadCompletionChannel>(Source->Executor(), 1);
        Net::co_spawn(Source->Executor(), RunMemoryPendingRead(Source, ReadDone),
                      [ChildException, Done](std::exception_ptr Error)
                      {
                          *ChildException = std::move(Error);
                          (void)Done->try_send(boost::system::error_code{});
                      });
        co_await Net::post(Source->Executor(), Net::use_awaitable);
        const auto CancelResult = Source->Cancel();
        co_await Done->async_receive(Net::use_awaitable);
        Net::steady_timer Wait(Source->Executor());
        Wait.expires_after(std::chrono::milliseconds(20));
        co_await Wait.async_wait(Net::use_awaitable);
        const auto FinalClose = Source->Close();
        const auto DrainResult = co_await Source->Activity()->Drain();
        EXPECT_TRUE(FinalClose.has_value());
        EXPECT_TRUE(CancelResult.has_value());
        EXPECT_TRUE(DrainResult.has_value());
    }

    /** @brief 读取具有 20 毫秒 deadline 的挂起流并保留 Timeout 结果。 */
    auto RunMemoryTimeoutRead(const std::shared_ptr<Prism::MemoryStream> &Source,
                              const std::shared_ptr<bool> &ReadDone) -> Net::awaitable<void>
    {
        std::array<std::byte, 8> Buffer{};
        const auto Result = co_await Source->ReadSome(Buffer);
        EXPECT_EQ(Result.Bytes, 0U);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Timeout);
        *ReadDone = true;
    }

    /** @brief 设置原 20/50 毫秒期限并等待 timeout read 完整退栈。 */
    auto RunMemoryTimeoutWhilePending(const std::shared_ptr<Prism::MemoryStream> &Source,
                                      const std::shared_ptr<bool> &ReadDone,
                                      const std::shared_ptr<std::exception_ptr> &ChildException)
        -> Net::awaitable<void>
    {
        Source->SetTimeout(std::chrono::milliseconds(20));
        const auto Done = std::make_shared<ReadCompletionChannel>(Source->Executor(), 1);
        Net::co_spawn(Source->Executor(), RunMemoryTimeoutRead(Source, ReadDone),
                      [ChildException, Done](std::exception_ptr Error)
                      {
                          *ChildException = std::move(Error);
                          (void)Done->try_send(boost::system::error_code{});
                      });
        Net::steady_timer Wait(Source->Executor());
        Wait.expires_after(std::chrono::milliseconds(50));
        co_await Wait.async_wait(Net::use_awaitable);
        co_await Done->async_receive(Net::use_awaitable);
        const auto FinalClose = Source->Close();
        const auto DrainResult = co_await Source->Activity()->Drain();
        EXPECT_TRUE(FinalClose.has_value());
        EXPECT_TRUE(DrainResult.has_value());
    }

    /** @brief 保留 50 毫秒异步读超时和至少 40 毫秒的 elapsed 门槛。 */
    auto RunAsyncReadTimeout(Prism::MemoryStream &Source) -> Net::awaitable<void>
    {
        Source.SetTimeout(std::chrono::milliseconds(50));
        std::array<std::uint8_t, 16> Buffer{};
        const auto Started = std::chrono::steady_clock::now();
        const auto Result = co_await Source.ReadSome(std::as_writable_bytes(std::span(Buffer)));
        const auto Elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - Started)
                                 .count();
        EXPECT_EQ(Result.Bytes, 0U);
        EXPECT_GE(Elapsed, 40);
    }

    /** @brief 原 timeout=0 读操作等待两个 executor post 后的四字节写入。 */
    auto RunDelayedWrite(Prism::MemoryStream &Destination) -> Net::awaitable<void>
    {
        co_await Net::post(Destination.Executor(), Net::use_awaitable);
        co_await Net::post(Destination.Executor(), Net::use_awaitable);
        std::array<std::byte, 4> Data{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
        (void)(co_await Destination.WriteExact(std::as_bytes(std::span(Prism::AsU8(Data)))));
    }

    /** @brief timeout=0 时等待既有 delayed writer 并核对 read 与协程完成。 */
    auto RunAsyncReadTimeoutDisabled(Prism::MemoryStream &Source, Prism::MemoryStream &Destination)
        -> Net::awaitable<void>
    {
        Source.SetTimeout(std::chrono::milliseconds(0));
        const auto Done = std::make_shared<ReadCompletionChannel>(Source.Executor(), 1);
        const auto Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(Source.Executor(), RunDelayedWrite(Destination), [Failure, Done](std::exception_ptr Error)
                      {
                          *Failure = std::move(Error);
                          (void)Done->try_send(boost::system::error_code{});
                      });
        std::array<std::uint8_t, 16> Buffer{};
        const auto Result = co_await Source.ReadSome(std::as_writable_bytes(std::span(Buffer)));
        EXPECT_EQ(Result.Bytes, 4U);
        co_await Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(*Failure);
    }

    /** @brief 经基类引用半关闭写方向，并等待另一端观察原 EOF。 */
    auto RunInterfaceShutdownEof(Prism::Transmission &Source,
                                 Prism::MemoryStream &Destination) -> Net::awaitable<void>
    {
        const auto ShutdownResult = co_await Source.WriteShutdown();
        EXPECT_TRUE(ShutdownResult.has_value());
        std::array<std::uint8_t, 8> Buffer{};
        const auto Result = co_await Destination.ReadSome(std::as_writable_bytes(std::span(Buffer)));
        EXPECT_EQ(Result.Bytes, 0U);
    }

    /** @brief 经基类引用设置原 timeout 并确认 MemoryStream 返回 Timeout。 */
    auto RunInterfaceSetTimeout(Prism::Transmission &BaseCarrier,
                                Prism::MemoryStream &Source) -> Net::awaitable<void>
    {
        BaseCarrier.SetTimeout(std::chrono::milliseconds(20));
        std::array<std::byte, 8> Buffer{};
        const auto Result = co_await Source.ReadSome(Buffer);
        EXPECT_EQ(Result.Bytes, 0U);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Timeout);
    }

}

TEST(Transport, MemoryPairEcho)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    RunCoro(Io, RunMemoryPairEcho(*Pair.FirstOwner, *Pair.SecondOwner));
    const auto FirstClose = Prism::Testing::DriveClose(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(FirstClose);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, MemoryPairCloseSemantics)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    RunCoro(Io, RunMemoryPairCloseSemantics(*Pair.FirstOwner, *Pair.SecondOwner));
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, ReadTimeout)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    bool TimedOut = false;
    RunCoro(Io, RunReadTimeout(*Pair.FirstOwner, TimedOut));
    EXPECT_TRUE(TimedOut);
    const auto FirstClose = Prism::Testing::DriveClose(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(FirstClose);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, ShutdownSemantics)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    RunCoro(Io, RunShutdownSemantics(*Pair.FirstOwner, *Pair.SecondOwner));
    const auto FirstClose = Prism::Testing::DriveClose(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(FirstClose);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, CancelSemantics)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    RunCoro(Io, RunCancelSemantics(*Pair.FirstOwner));
    const auto FirstClose = Prism::Testing::DriveClose(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(FirstClose);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, MemoryStreamCloseWhileReadPending)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    auto Source = std::make_shared<Prism::MemoryStream>(std::move(*Pair.FirstOwner));
    auto ReadDone = std::make_shared<bool>(false);
    auto ChildException = std::make_shared<std::exception_ptr>();
    RunCoro(Io, RunMemoryCloseWhilePending(Source, ReadDone, ChildException));
    ASSERT_FALSE(*ChildException);
    EXPECT_TRUE(*ReadDone);
    const auto SourceDrain = Prism::Testing::DriveDrain(Io, Source);
    const auto PeerClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    EXPECT_TRUE(SourceDrain.has_value());
    Prism::Testing::ExpectFixtureCloseReceipt(PeerClose);
}

TEST(Transport, MemoryStreamCancelWhileReadPending)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    auto Source = std::make_shared<Prism::MemoryStream>(std::move(*Pair.FirstOwner));
    auto ReadDone = std::make_shared<bool>(false);
    auto ChildException = std::make_shared<std::exception_ptr>();
    RunCoro(Io, RunMemoryCancelWhilePending(Source, ReadDone, ChildException));
    ASSERT_FALSE(*ChildException);
    EXPECT_TRUE(*ReadDone);
    const auto SourceClose = Prism::Testing::DriveClose(Io, Source);
    const auto PeerClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(SourceClose);
    Prism::Testing::ExpectFixtureCloseReceipt(PeerClose);
}

TEST(Transport, MemoryStreamTimeoutWhileReadPending)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    auto Source = std::make_shared<Prism::MemoryStream>(std::move(*Pair.FirstOwner));
    auto ReadDone = std::make_shared<bool>(false);
    auto ChildException = std::make_shared<std::exception_ptr>();
    RunCoro(Io, RunMemoryTimeoutWhilePending(Source, ReadDone, ChildException));
    ASSERT_FALSE(*ChildException);
    EXPECT_TRUE(*ReadDone);
    const auto SourceClose = Prism::Testing::DriveClose(Io, Source);
    const auto PeerClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(SourceClose);
    Prism::Testing::ExpectFixtureCloseReceipt(PeerClose);
}

TEST(Transport, AsyncReadTimeoutError)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    RunCoro(Io, RunAsyncReadTimeout(*Pair.FirstOwner));
    const auto FirstClose = Prism::Testing::DriveClose(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(FirstClose);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, AsyncReadTimeoutDisabled)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    RunCoro(Io, RunAsyncReadTimeoutDisabled(*Pair.FirstOwner, *Pair.SecondOwner));
    const auto FirstClose = Prism::Testing::DriveClose(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(FirstClose);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, InterfaceTransmissionLike)
{
    static_assert(Prism::TransmissionLike<Prism::MemoryStream>);
    static_assert(Prism::TransmissionLike<Prism::Transport::Reliable>);
}

TEST(Transport, InterfaceIsOpen)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    EXPECT_TRUE(Pair.FirstOwner->IsOpen());
    const auto CloseResult = Pair.FirstOwner->Close();
    Io.run();
    EXPECT_FALSE(Pair.FirstOwner->IsOpen());
    const auto FirstDrain = Prism::Testing::DriveDrain(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    EXPECT_TRUE(CloseResult.has_value());
    EXPECT_TRUE(FirstDrain.has_value());
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, InterfaceShutdownEof)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    Prism::Transmission& Source = *Pair.FirstOwner;
    RunCoro(Io, RunInterfaceShutdownEof(Source, *Pair.SecondOwner));
    const auto FirstClose = Prism::Testing::DriveClose(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(FirstClose);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}

TEST(Transport, InterfaceSetTimeoutPolymorphic)
{
    Net::io_context Io;
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Io.get_executor());
    Prism::Transmission* BaseCarrier = Pair.FirstOwner.get();
    RunCoro(Io, RunInterfaceSetTimeout(*BaseCarrier, *Pair.FirstOwner));
    const auto FirstClose = Prism::Testing::DriveClose(Io, Pair.FirstOwner);
    const auto SecondClose = Prism::Testing::DriveClose(Io, Pair.SecondOwner);
    Prism::Testing::ExpectFixtureCloseReceipt(FirstClose);
    Prism::Testing::ExpectFixtureCloseReceipt(SecondClose);
}
