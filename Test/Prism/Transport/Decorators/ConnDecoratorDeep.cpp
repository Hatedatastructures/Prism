/**
 * @file ConnDecoratorDeep.cpp
 * @brief 测试库 Conn 装饰器剩余方法深度测试
 * @details 覆盖 gun / reality / anytls / tuic 四个 Conn 装饰器的
 *          Executor / Cancel / NextLayer（const + 非 const）/ Release
 *          / Close 等透传方法，以及 Mux::StreamTransmission 的
 *          owner 校验、终止请求与真实排空路径。
 */

#include <boost/asio/co_spawn.hpp>
#include "../Core/Resources.hpp"
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <stdexcept>
#include <string>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Prism/MockTransport.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Protocols/Tuic/Connection/Connection.hpp>
#include <Prism/Protocols/Anytls/Conn.hpp>
#include <Prism/Protocols/Gun/Conn.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Anytls = Prism::Anytls;
    namespace Gun = Prism::Gun;
    namespace Mux = Prism::Mux;
    namespace Tuic = Prism::Tuic;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        // 同一 io_context 可能被多次驱动，restart() 重置 stopped 标志
        IoContext.restart();
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    class ZeroProgressTransport final : public Prism::Transmission
    {
    public:
        explicit ZeroProgressTransport(Net::any_io_executor Executor)
            : Prism::Transmission(Executor), Executor_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::error_code Error;
            Error = std::make_error_code(std::errc::operation_canceled);
            { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(Error)}); return; }
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Error;
            ++Writes_;
            BufferSize_ = Buffer.size();
            if (Writes_ == 1)
            {
                Error.clear();
                if (Overreport_)
                {
                    { std::move(Handler)(Prism::IoResult{BufferSize_ + 1, Prism::Fault::FromNative(Error)}); return; }
                }
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(Error)}); return; }
            }
            Error = std::make_error_code(std::errc::broken_pipe);
            { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(Error)}); return; }
        }

        auto OnClose() -> ControlResult override
        {
            return {};
        }
        auto OnCancel() -> ControlResult override
        {
            return {};
        }

        std::size_t Writes_{0};
        std::size_t BufferSize_{0};
        bool Overreport_{false};

    private:
        Net::any_io_executor Executor_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }
    };

    TEST(ConnDecorator, AnytlsZeroProgressWriteFailsImmediately)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<ZeroProgressTransport>(Ioc.get_executor());
        auto Conn = std::make_shared<Anytls::Conn<>>(Transport, "password");
        std::expected<void, Prism::Fault::Failure> Result;

        RunCoroutine(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Conn->WriteHandshake(0);
                 });

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::WouldBlock);
        EXPECT_EQ(Transport->Writes_, 1u);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, Transport));
    }

    TEST(ConnDecorator, AnytlsOverreportedWriteFailsImmediately)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<ZeroProgressTransport>(Ioc.get_executor());
        Transport->Overreport_ = true;
        auto Conn = std::make_shared<Anytls::Conn<>>(Transport, "password");
        std::expected<void, Prism::Fault::Failure> Result;

        RunCoroutine(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Conn->WriteHandshake(0);
                 });

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_EQ(Transport->Writes_, 1u);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, Transport));
    }

    TEST(ConnDecorator, AnytlsOverreportedReadFailsImmediately)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        Transport->OverreportRead = true;
        auto Conn = std::make_shared<Anytls::Conn<>>(Transport, "password");
        std::expected<void, Prism::Fault::Failure> Result;

        RunCoroutine(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Conn->ReadHandshake();
                 });

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_EQ(Transport->ReadsDone, 1u);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, Transport));
    }

    /**
     * @brief 断言装饰器透传方法（Executor/Cancel/NextLayer/Release/Close）
     */
    template <typename DecoT>
    auto CheckDecorator(const std::shared_ptr<DecoT> &ConnT, Net::io_context &IoContext) -> void
    {
        (void)IoContext;
        (void)ConnT->Executor();
        EXPECT_NE(ConnT->NextLayer(), nullptr);
        const auto *Connection = ConnT.get();
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_EQ(ConnT->template lowest_layer<MemoryStream>(), ConnT->NextLayer());
        IoContext.restart();
        const auto CancelResult = ConnT->Cancel();
        const auto CloseResult = ConnT->Close();
        IoContext.run();
        EXPECT_TRUE(CancelResult.has_value());
        EXPECT_TRUE(CloseResult.has_value());
        EXPECT_TRUE(Prism::Testing::DriveDrain(IoContext, ConnT).has_value());
        auto Released = ConnT->Release();
        EXPECT_NE(Released, nullptr);
        EXPECT_EQ(ConnT->NextLayer(), nullptr);
        EXPECT_TRUE(Prism::Testing::DriveDrain(IoContext, Released).has_value());
    }

    /**
     * @brief 验证 Gun 连接未握手时读写立即返回 NotOpen。
     * @param Conn 要检查的 Gun 连接 owner。
     * @return 完成读写错误边界断言的异步操作。
     */
    auto RunGunNotOpenScenario(std::shared_ptr<Gun::Conn<>> Conn)
        -> Net::awaitable<void>
    {
        Prism::Fault::Failure ErrorCode;
        std::array<std::byte, 4> Buffer{};
        const auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Conn->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 0u);
        EXPECT_TRUE(ErrorCode.Failed());
        EXPECT_EQ(ErrorCode.Native, make_error_code(Error::NotOpen));
        ErrorCode = {};
        const auto WriteCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Conn->WriteSome(std::span<const std::byte>(Buffer)));
        EXPECT_EQ(WriteCount, 0u);
        EXPECT_EQ(ErrorCode.Native, make_error_code(Error::NotOpen));
    }

    /**
     * @brief 验证 Gun 握手后数据面保留连接头和载荷。
     * @param Conn Gun 连接 owner。
     * @param Peer 接收连接头和数据面载荷的内存传输。
     * @return 完成握手、写入和 peer 读取断言的异步操作。
     */
    auto RunGunDataTransferScenario(
        std::shared_ptr<Gun::Conn<>> Conn,
        std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto Handshake = co_await Conn->WriteHandshake("example.com");
        EXPECT_TRUE(Handshake);
        if (!Handshake) co_return;
        std::array<std::byte, 8> WriteBuffer{std::byte{0x42}};
        Prism::Fault::Failure ErrorCode;
        EXPECT_EQ(([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Conn->WriteSome(std::span<const std::byte>(WriteBuffer))),
                   8u);

        // 先读 CONNECT 握手头（"CONNECT example.com HTTP/2\r\n\r\n" 共 30 字节），
        // 再验证数据面载荷原样透传。
        std::array<std::byte, 64> Header{};
        const auto HeaderBytes = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Peer->ReadSome(std::span<std::byte>(Header)));
        EXPECT_EQ(HeaderBytes, 30u);
        std::array<std::byte, 8> ReadBuffer{};
        const auto PayloadBytes = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Peer->ReadSome(std::span<std::byte>(ReadBuffer)));
        EXPECT_EQ(PayloadBytes, 8u);
        if (PayloadBytes == 8u)
        {
            EXPECT_EQ(static_cast<std::uint8_t>(ReadBuffer[0]), 0x42);
        }
    }

    /**
     * @brief 验证已取消的 Mux stream 仍可完成幂等关闭和终止排空。
     * @param Session 已建立并由调用方持有的 Mux session。
     * @return 完成取消、读错误、关闭和最终排空断言的异步操作。
     */
    auto RunStreamTransmissionScenario(auto Session) -> Net::awaitable<void>
    {
        auto Handle = co_await Session->OpenStream();
        if (!Handle)
        {
            EXPECT_TRUE(false) << "OpenStream Failed";
            co_return;
        }
        auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
        EXPECT_TRUE(Stream->IsOpen());
        EXPECT_EQ(Stream->Handle(), Handle);
        std::array<std::byte, 4> Buffer{};
        auto PendingRead = Net::co_spawn(Stream->Executor(), Stream->ReadSome(Buffer),
            Net::use_awaitable);
        co_await Net::post(Stream->Executor(), Net::use_awaitable);
        const auto CancelResult = Stream->Cancel();
        EXPECT_TRUE(CancelResult.has_value());
        const auto Read = co_await std::move(PendingRead);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Prism::Fault::Code::Canceled);
        // 非空句柄 Close / Reset（co_spawn 投递）。
        const auto CloseResult = Stream->Close();
        Stream->Reset();
        const auto DrainResult = co_await Stream->DrainTerminations();
        EXPECT_TRUE(DrainResult);
        EXPECT_TRUE(CloseResult.has_value());
        EXPECT_FALSE(Stream->IsOpen());
        co_await Session->Close();
    }

    TEST(ConnDecorator, GunConn)
    {
        Net::io_context Ioc;
        auto MemoryPair6 = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair6.FirstOwner;
        auto& Remote = *MemoryPair6.SecondOwner;
        auto Peer = std::make_shared<MemoryStream>(std::move(Remote));
        auto Conn = std::make_shared<Gun::Conn<>>(
            std::make_shared<MemoryStream>(std::move(Local)));

        // 未握手读写 → not_open
        RunCoroutine(Ioc, RunGunNotOpenScenario(Conn));

        // 客户端握手 → 数据面透传
        RunCoroutine(Ioc, RunGunDataTransferScenario(Conn, Peer));

        CheckDecorator(Conn, Ioc);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, Peer));
    }

    TEST(ConnDecorator, AnyTlsConn)
    {
        Net::io_context Ioc;
        auto MemoryPair4 = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair4.FirstOwner;
        auto& Remote = *MemoryPair4.SecondOwner;
        auto Conn =
            std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(Local)), "Secret");
        CheckDecorator(Conn, Ioc);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, MemoryPair4.SecondOwner));
    }

    TEST(ConnDecorator, TuicConn)
    {
        Net::io_context Ioc;
        auto MemoryPair3 = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair3.FirstOwner;
        auto& Remote = *MemoryPair3.SecondOwner;
        auto Conn = std::make_shared<Tuic::Conn<>>(std::make_shared<MemoryStream>(std::move(Local)),
                                                 std::array<std::uint8_t, 16>{});
        CheckDecorator(Conn, Ioc);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, MemoryPair3.SecondOwner));
    }

    auto RunRetiredStreamClose(Net::io_context &Context) -> Net::awaitable<void>
    {
        auto MemoryPair2 = Prism::Testing::MakeOwnedTransportPair(Context.get_executor());
        auto& Local = *MemoryPair2.FirstOwner;
        auto& Peer = *MemoryPair2.SecondOwner;
        auto Transport = std::make_shared<MemoryStream>(std::move(Local));
        auto Client = Mux::Smux::Connect(Transport);
        const auto Session = Client.Session();
        const auto Handle = co_await Session->OpenStream();
        EXPECT_TRUE(Handle);
        if (!Handle) co_return;
        const auto Tasks = Handle->Tasks();
        auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
        co_await Handle->Close();
        EXPECT_FALSE(Handle->Tasks());
        const auto StartedBefore = Tasks->Stats().Started;
        const auto CloseResult = Stream->Close();
        const auto RepeatedCloseResult = Stream->Close();
        Stream->Reset();
        const auto ShutdownResult = co_await Stream->WriteShutdown();
        const auto DrainResult = co_await Stream->DrainTerminations();
        EXPECT_TRUE(DrainResult);
        EXPECT_TRUE(CloseResult.has_value());
        EXPECT_TRUE(RepeatedCloseResult.has_value());
        EXPECT_FALSE(ShutdownResult.has_value());
        EXPECT_EQ(ShutdownResult.error().Code, Prism::Fault::Code::Canceled);
        EXPECT_FALSE(Stream->IsOpen());
        EXPECT_EQ(Tasks->Stats().Started, StartedBefore);
        co_await Session->Close();
        const auto PeerClose = Peer.Close();
        const auto PeerDrain = co_await Peer.Activity()->Drain();
        EXPECT_TRUE(PeerClose.has_value());
        EXPECT_TRUE(PeerDrain.has_value());
    }

    TEST(ConnDecorator, RepeatedCloseAfterHandleRetirementDoesNotSubmitTask)
    {
        Net::io_context Context;
        std::exception_ptr Failure;
        Net::co_spawn(Context, RunRetiredStreamClose(Context),
            [&Failure](std::exception_ptr Error) { Failure = Error; });
        Context.run();
        EXPECT_FALSE(Failure);
    }

    TEST(ConnDecorator, StreamTransmission)
    {
        Net::io_context Ioc;
        auto MemoryPair1 = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair1.FirstOwner;
        auto& Remote = *MemoryPair1.SecondOwner;

        EXPECT_THROW(std::make_shared<Mux::StreamTransmission>(nullptr), std::invalid_argument);

        // 非空句柄：Cancel 生效
        auto Transport = std::make_shared<MemoryStream>(std::move(Local));
        auto Client = Mux::Smux::Connect(Transport);
        auto Session = Client.Session();
        EXPECT_TRUE(Client.IsOpen());
        RunCoroutine(Ioc, RunStreamTransmissionScenario(Session));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, Transport));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, MemoryPair1.SecondOwner));
    }

} // namespace
