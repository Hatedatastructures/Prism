/**
 * @file EncryptedDecoratorTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "TransportDecoratorTestSupport.hpp"
#include "TransportResources.hpp"

namespace
{
    struct HandshakeFailureRequest final
    {
        Net::io_context &Ioc;
        Ssl::context &ServerContext;
        Encrypted::HandshakeResult &Result;
    };

    /**
     * @brief 发送非 TLS 输入并验证握手失败时恢复底层 transport。
     * @param Request 失败握手所需的执行器、SSL context 和结果槽。
     * @return 完成垃圾输入写入与服务端握手的异步操作。
     * @details memory stream 由本协程局部 shared owner 持有到握手结果产生。
     */
    auto RunHandshakeFailureScenario(HandshakeFailureRequest Request)
        -> Net::awaitable<void>
    {
        auto MemoryPair13 = Preview::Testing::MakeOwnedTransportPair(Request.Ioc.get_executor());
        auto& Local = *MemoryPair13.FirstOwner;
        auto& Remote = *MemoryPair13.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));

        // 客户端发送非 TLS 垃圾数据。
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("GARBAGE-not-a-Client-hello")));
        Request.Result = co_await Encrypted::SslHandshake({Destination, Request.ServerContext, std::chrono::steady_clock::now() + Encrypted::DefaultHandshakeTimeout, Preview::Testing::MakeTransportBytes()});
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Destination));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
    }

    struct TlsRoundTripRequest final
    {
        Net::io_context &Ioc;
        Ssl::context &ServerContext;
        Ssl::context &ClientContext;
    };

    /**
     * @brief 在 memory pipe 的客户端侧执行 TLS 握手。
     * @param Source 客户端拥有的 memory stream。
     * @param ClientContext 客户端 SSL context。
     * @return 已完成握手的 TLS stream。
     */
    auto RunClientHandshake(
        std::shared_ptr<Preview::MemoryStream> Source,
        Ssl::context &ClientContext) -> Net::awaitable<Encrypted::SharedStream>
    {
        Preview::Transport::Connector Connector(std::move(Source));
        auto Stream = std::make_shared<Encrypted::StreamType>(
            std::move(Connector), ClientContext);
        boost::system::error_code ErrorCode;
        co_await Stream->async_handshake(
            Ssl::stream_base::client,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        EXPECT_FALSE(ErrorCode) << ErrorCode.message();
        co_return Stream;
    }

    /**
     * @brief 在 memory pipe 上完成双向 TLS 握手、payload 往返和关闭。
     * @param Request 执行器及服务端、客户端 SSL context。
     * @return 完成握手、双向读写和最终关闭的异步操作。
     * @details 两个 handshake awaitable 保留各自 stream owner，传输完成后显式 Cancel 和 Close。
     */
    auto RunTlsRoundTripScenario(TlsRoundTripRequest Request) -> Net::awaitable<void>
    {
        auto MemoryPair12 = Preview::Testing::MakeOwnedTransportPair(Request.Ioc.get_executor());
        auto& Local = *MemoryPair12.FirstOwner;
        auto& Remote = *MemoryPair12.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));

        // 服务端握手。
        auto ServerHandshake = [Destination, &Request]()
            -> Net::awaitable<Encrypted::SharedStream>
        {
            auto Handshake = co_await Encrypted::SslHandshake(
                {Destination, Request.ServerContext, std::chrono::steady_clock::now() + Encrypted::DefaultHandshakeTimeout, Preview::Testing::MakeTransportBytes()});
            EXPECT_EQ(Handshake.Failure.Code, Preview::Fault::Code::Success);
            co_return std::move(Handshake.Stream);
        };

        auto [ServerStream, ClientStream] =
            co_await (ServerHandshake() &&
                      RunClientHandshake(Source, Request.ClientContext));
        if (!ServerStream || !ClientStream)
        {
            EXPECT_TRUE(false) << "TLS handshake Failed";
            Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
            Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Destination));
            co_return;
        }

        auto ServerTransport = std::make_shared<Encrypted>(ServerStream, Preview::Testing::MakeTransportBytes());
        auto ClientTransport = std::make_shared<Encrypted>(ClientStream, Preview::Testing::MakeTransportBytes());

        // 装饰器访问器（NextLayer 穿透 ssl::Stream → Connector 到底层）。
        EXPECT_EQ(ClientTransport->TransportType(), Preview::Transmission::Type::Tcp);
        EXPECT_NE(ClientTransport->NextLayer(), nullptr);

        // 客户端 → 服务端（加密写 → 解密读）。
        Preview::Fault::Failure ErrorCode;
        const auto ClientWritten = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientTransport->WriteSome(SvBytes("hello")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(ClientWritten, 5u);
        std::array<std::byte, 16> Buffer{};
        auto ServerReadCount = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ServerTransport->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ServerReadCount, 5u);
        EXPECT_EQ(Preview::AsStrView(
                      Preview::AsU8(std::span<std::byte>(Buffer).first(5))),
                   "hello");

        // 服务端 → 客户端。
        const auto ServerWritten = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ServerTransport->WriteSome(SvBytes("world")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(ServerWritten, 5u);
        auto ClientReadCount = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientTransport->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ClientReadCount, 5u);
        EXPECT_EQ(Preview::AsStrView(
                      Preview::AsU8(std::span<std::byte>(Buffer).first(5))),
                   "world");

        // 大块往返。
        std::vector<std::byte> Payload(4096, std::byte{0x77});
        const auto PayloadWritten = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientTransport->WriteExact(std::span<const std::byte>(Payload)));
        EXPECT_EQ(PayloadWritten, Payload.size());
        std::vector<std::byte> Received(Payload.size());
        const auto PayloadRead = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ServerTransport->ReadExact(std::span<std::byte>(Received)));
        EXPECT_EQ(PayloadRead, Payload.size());
        EXPECT_EQ(std::memcmp(Received.data(), Payload.data(), Payload.size()), 0);

        // Close/Cancel 不崩溃（SSL_shutdown + 底层关闭）。
        const auto ClientCancel = ClientTransport->Cancel();
        const auto ServerCancel = ServerTransport->Cancel();
        const auto ClientClose = ClientTransport->Close();
        const auto ServerClose = ServerTransport->Close();
        const auto ClientDrain = co_await ClientTransport->Activity()->Drain();
        const auto ServerDrain = co_await ServerTransport->Activity()->Drain();
        EXPECT_TRUE(ClientCancel.has_value());
        EXPECT_TRUE(ServerCancel.has_value());
        EXPECT_TRUE(ClientClose.has_value());
        EXPECT_TRUE(ServerClose.has_value());
        EXPECT_TRUE(ClientDrain.has_value());
        EXPECT_TRUE(ServerDrain.has_value());
        EXPECT_TRUE((co_await Source->Activity()->Drain()).has_value());
        EXPECT_TRUE((co_await Destination->Activity()->Drain()).has_value());
    }
} // namespace

TEST(PreviewEncryptedDecorator, SslHandshakeNullInbound)
    {
        Net::io_context Ioc;
        Ssl::context Context(Ssl::context::tls_server);
        Encrypted::HandshakeResult Result;
        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Encrypted::SslHandshake({nullptr, Context, std::chrono::steady_clock::now() + Encrypted::DefaultHandshakeTimeout, Preview::Testing::MakeTransportBytes()});
                 });
        const auto Code = Result.Failure.Code;
        const auto &Stream = Result.Stream;
        const auto &Recovered = Result.Recovered;
        EXPECT_EQ(Code, Preview::Fault::Code::InvalidArgument);
        EXPECT_EQ(Stream, nullptr);
        EXPECT_EQ(Recovered, nullptr);
    }

TEST(PreviewEncryptedDecorator, HandshakeFailureRecoversTransport)
    {
        Net::io_context Ioc;
        Ssl::context ServerContext(Ssl::context::tls_server);
        LoadSelfSignedCert(ServerContext);

        Encrypted::HandshakeResult Result;
        std::exception_ptr CoroutineException;
        Net::co_spawn(
            Ioc,
            RunHandshakeFailureScenario(
                HandshakeFailureRequest{Ioc, ServerContext, Result}),
            [&](std::exception_ptr Error)
            {
                CoroutineException = Error;
            });
        Ioc.run();

        if (CoroutineException)
        {
            try
            {
                std::rethrow_exception(CoroutineException);
            }
            catch (const std::exception &Exception)
            {
                printf("DBG coroutine exception: %s\n", Exception.what());
            }
        }
        printf("DBG Code=%d Stream=%p recovered=%p\n",
               static_cast<int>(Result.Failure.Code), (void *)Result.Stream.get(),
               (void *)Result.Recovered.get());

        const auto Code = Result.Failure.Code;
        const auto &Stream = Result.Stream;
        const auto &Recovered = Result.Recovered;
        EXPECT_NE(Code, Preview::Fault::Code::Success);
        EXPECT_EQ(Stream, nullptr);
        ASSERT_NE(Recovered, nullptr); // 失败后从 Connector 恢复底层传输
        EXPECT_EQ(Recovered->TransportType(), Preview::Transmission::Type::Tcp);
    }

TEST(PreviewEncryptedDecorator, TlsRoundTripOverMemoryPipe)
    {
        Net::io_context Ioc;
        Ssl::context ServerContext(Ssl::context::tls_server);
        LoadSelfSignedCert(ServerContext);
        Ssl::context ClientContext(Ssl::context::tls_client);
        ClientContext.set_verify_mode(Ssl::verify_none);

        RunCoro(Ioc, RunTlsRoundTripScenario(
                         TlsRoundTripRequest{Ioc, ServerContext, ClientContext}));
    }

TEST(PreviewEncryptedDecorator, AccessorsAndRelease)
    {
        Net::io_context Ioc;
        Ssl::context Context(Ssl::context::tls_server);

        auto MemoryPair11 = Preview::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair11.FirstOwner;
        auto& Remote = *MemoryPair11.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        Preview::Transport::Connector Connector(Source);
        auto Stream = std::make_shared<Encrypted::StreamType>(
            std::move(Connector), Context);

        auto Transport = std::make_shared<Encrypted>(Stream, Preview::Testing::MakeTransportBytes());
        EXPECT_EQ(Transport->TransportType(), Preview::Transmission::Type::Tcp);
        EXPECT_NE(Transport->NextLayer(), nullptr);
        EXPECT_EQ(Transport->Stream().native_handle(), Stream->native_handle());
        EXPECT_NO_THROW((void)Transport->Executor());

        // Close/Cancel（未握手流上安全）
        Preview::Transmission::ControlResult CancelResult;
        EXPECT_NO_THROW(CancelResult = Transport->Cancel());
        EXPECT_TRUE(CancelResult.has_value());
        Preview::Transmission::ControlResult CloseResult;
        EXPECT_NO_THROW(CloseResult = Transport->Close());
        EXPECT_TRUE(CloseResult.has_value());
        Ioc.run();
        EXPECT_TRUE(Preview::Testing::DriveDrain(Ioc, Transport).has_value());
        auto Released = Transport->ReleaseStream();
        EXPECT_EQ(Released.value().get(), Stream.get());
        EXPECT_TRUE(Preview::Testing::DriveDrain(Ioc, Source).has_value());
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, MemoryPair11.SecondOwner));
    }
