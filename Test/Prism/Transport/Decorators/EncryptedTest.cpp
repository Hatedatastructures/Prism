/**
 * @file EncryptedTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "../Core/DecoratorSupport.hpp"
#include "../Core/Resources.hpp"

#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/TlsStream.hpp>
#include <Prism/Transport/Connector.hpp>
#include <Prism/Foundation/Fault/Code.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/system/error_code.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace
{
    template <typename Error>
    auto RequireBoostErrorCode(Error Value) -> boost::system::error_code
    {
        static_assert(std::is_same_v<Error, boost::system::error_code>);
        return Value;
    }

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
        auto MemoryPair13 = Prism::Testing::MakeOwnedTransportPair(Request.Ioc.get_executor());
        auto& Local = *MemoryPair13.FirstOwner;
        auto& Remote = *MemoryPair13.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));

        // 客户端发送非 TLS 垃圾数据。
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("GARBAGE-not-a-Client-hello")));
        Request.Result = co_await Encrypted::SslHandshake({Destination, Request.ServerContext, std::chrono::steady_clock::now() + Encrypted::DefaultHandshakeTimeout, Prism::Testing::MakeTransportBytes()});
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Destination));
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    struct TlsRoundTripRequest final
    {
        Net::io_context &Ioc;
        Ssl::context &ServerContext;
        Ssl::context &ClientContext;
    };

    struct MoveOnlyShutdownResult final
    {
        std::size_t CompletionCount{0};
        std::size_t CapturedValue{0};
        bool Succeeded{false};
        bool OnAssociatedExecutor{false};
        bool OperationAliveDuringCallback{false};

        auto RecordCompletion(std::size_t Value, bool OnExecutor, bool OperationAlive) -> void
        {
            CapturedValue = Value;
            OnAssociatedExecutor = OnExecutor;
            OperationAliveDuringCallback = OperationAlive;
        }

        auto RecordResult(boost::system::error_code Error) -> void
        {
            Succeeded = !Error;
        }
    };

    struct NativeTlsReadErrorResult final
    {
        std::size_t CompletionCount{0};
        std::size_t Bytes{1};
        boost::system::error_code Error;
        bool OnAssociatedExecutor{false};
        bool OperationAliveDuringCallback{false};
        bool CarrierAliveDuringCallback{false};
        bool ClientActivityDrained{false};
        bool CarrierRetiredAfterDrain{false};
        bool ServerActivityDrained{false};
        bool RawEndpointsDrained{false};
    };

    struct NativeTlsReadErrorRequest final
    {
        TlsRoundTripRequest RoundTrip;
        NativeTlsReadErrorResult& Result;
    };

    template<class Strand>
    struct NativeTlsReadErrorCompletion final
    {
        NativeTlsReadErrorResult& Result;
        Strand& UserStrand;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
        std::weak_ptr<Prism::Transport::TlsStream> Carrier;
        Net::steady_timer& CompletionSignal;

        auto operator()(boost::system::error_code Error, std::size_t Bytes) -> void
        {
            ++Result.CompletionCount;
            Result.Bytes = Bytes;
            Result.Error = Error;
            Result.OnAssociatedExecutor = UserStrand.running_in_this_thread();
            Result.OperationAliveDuringCallback = !Activity->IsRetired();
            Result.CarrierAliveDuringCallback = !Carrier.expired();
            static_cast<void>(CompletionSignal.cancel());
        }
    };

    struct MoveOnlyCompletion final
    {
        MoveOnlyCompletion() = default;
        MoveOnlyCompletion(const MoveOnlyCompletion&) = delete;
        auto operator=(const MoveOnlyCompletion&) -> MoveOnlyCompletion& = delete;
        MoveOnlyCompletion(MoveOnlyCompletion&&) noexcept = default;
        auto operator=(MoveOnlyCompletion&&) noexcept -> MoveOnlyCompletion& = default;

        template<class... Args>
        auto operator()(Args&&...) -> void
        {
        }
    };

    static_assert(requires(
        Prism::Transport::TlsStream& Stream,
        MoveOnlyCompletion Handler,
        Net::mutable_buffer Input,
        Net::const_buffer Output)
    {
        Stream.async_read_some(Input, std::move(Handler));
        Stream.async_write_some(Output, std::move(Handler));
        Stream.async_handshake(Ssl::stream_base::client, std::move(Handler));
        Stream.async_shutdown(std::move(Handler));
        Stream.async_write_shutdown(std::move(Handler));
    });

    /**
     * @brief 在 memory pipe 的客户端侧执行 TLS 握手。
     * @param Source 客户端拥有的 memory stream。
     * @param ClientContext 客户端 SSL context。
     * @return 已完成握手的 TLS stream。
     */
    auto RunClientHandshake(
        std::shared_ptr<Prism::MemoryStream> Source,
        Ssl::context &ClientContext) -> Net::awaitable<Encrypted::SharedStream>
    {
        Prism::Transport::Connector Connector(std::move(Source));
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
        auto MemoryPair12 = Prism::Testing::MakeOwnedTransportPair(Request.Ioc.get_executor());
        auto& Local = *MemoryPair12.FirstOwner;
        auto& Remote = *MemoryPair12.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));

        // 服务端握手。
        auto ServerHandshake = [Destination, &Request]()
            -> Net::awaitable<Encrypted::SharedStream>
        {
            auto Handshake = co_await Encrypted::SslHandshake(
                {Destination, Request.ServerContext, std::chrono::steady_clock::now() + Encrypted::DefaultHandshakeTimeout, Prism::Testing::MakeTransportBytes()});
            EXPECT_EQ(Handshake.Failure.Code, Prism::Fault::Code::Success);
            co_return std::move(Handshake.Stream);
        };

        auto [ServerStream, ClientStream] =
            co_await (ServerHandshake() &&
                      RunClientHandshake(Source, Request.ClientContext));
        if (!ServerStream || !ClientStream)
        {
            EXPECT_TRUE(false) << "TLS handshake Failed";
            Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
            Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Destination));
            co_return;
        }

        auto ServerTransport = std::make_shared<Encrypted>(ServerStream, Prism::Testing::MakeTransportBytes());
        auto ClientTransport = std::make_shared<Encrypted>(ClientStream, Prism::Testing::MakeTransportBytes());

        // 装饰器访问器（NextLayer 穿透 ssl::Stream → Connector 到底层）。
        EXPECT_EQ(ClientTransport->TransportType(), Prism::Transmission::Type::Tcp);
        EXPECT_NE(ClientTransport->NextLayer(), nullptr);

        // 客户端 → 服务端（加密写 → 解密读）。
        Prism::Fault::Failure ErrorCode;
        const auto ClientWritten = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientTransport->WriteSome(SvBytes("hello")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(ClientWritten, 5u);
        std::array<std::byte, 16> Buffer{};
        auto ServerReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ServerTransport->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ServerReadCount, 5u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(5))),
                   "hello");

        // 服务端 → 客户端。
        const auto ServerWritten = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ServerTransport->WriteSome(SvBytes("world")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(ServerWritten, 5u);
        auto ClientReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientTransport->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ClientReadCount, 5u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(5))),
                   "world");

        // 大块往返。
        std::vector<std::byte> Payload(4096, std::byte{0x77});
        const auto PayloadWritten = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientTransport->WriteExact(std::span<const std::byte>(Payload)));
        EXPECT_EQ(PayloadWritten, Payload.size());
        std::vector<std::byte> Received(Payload.size());
        const auto PayloadRead = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ServerTransport->ReadExact(std::span<std::byte>(Received)));
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

    /**
     * @brief 在已握手 TLS 流上用 move-only token 完成本端写半关闭并验证反向读取。
     * @param Request TLS上下文、执行器及 completion 观察结果。
     * @return 完成一次写半关闭及反向数据往返的异步操作。
     */
    struct MoveOnlyShutdownRequest final
    {
        TlsRoundTripRequest RoundTrip;
        MoveOnlyShutdownResult& Result;
    };

    auto RunMoveOnlyShutdownScenario(MoveOnlyShutdownRequest Request)
        -> Net::awaitable<void>
    {
        auto MemoryPair = Prism::Testing::MakeOwnedTransportPair(
            Request.RoundTrip.Ioc.get_executor());
        auto Source = std::make_shared<Prism::MemoryStream>(
            std::move(*MemoryPair.FirstOwner));
        auto Destination = std::make_shared<Prism::MemoryStream>(
            std::move(*MemoryPair.SecondOwner));
        auto ServerHandshake = [Destination, &Request]()
            -> Net::awaitable<Encrypted::SharedStream>
        {
            auto Handshake = co_await Encrypted::SslHandshake({
                Destination, Request.RoundTrip.ServerContext,
                std::chrono::steady_clock::now() + Encrypted::DefaultHandshakeTimeout,
                Prism::Testing::MakeTransportBytes()});
            EXPECT_EQ(Handshake.Failure.Code, Prism::Fault::Code::Success);
            co_return std::move(Handshake.Stream);
        };
        auto [ServerStream, ClientStream] = co_await (
            ServerHandshake() &&
            RunClientHandshake(Source, Request.RoundTrip.ClientContext));
        if (!ServerStream || !ClientStream)
        {
            EXPECT_TRUE(false) << "TLS handshake Failed";
            Prism::Testing::ExpectFixtureCloseReceipt(
                co_await Prism::Testing::CloseFixture(Source));
            Prism::Testing::ExpectFixtureCloseReceipt(
                co_await Prism::Testing::CloseFixture(Destination));
            co_return;
        }

        auto ServerTransport = std::make_shared<Encrypted>(
            ServerStream, Prism::Testing::MakeTransportBytes());
        auto ClientTransport = std::make_shared<Encrypted>(
            ClientStream, Prism::Testing::MakeTransportBytes());
        auto UserStrand = Net::make_strand(Request.RoundTrip.Ioc.get_executor());
        Net::steady_timer CompletionSignal(Request.RoundTrip.Ioc);
        CompletionSignal.expires_at(std::chrono::steady_clock::time_point::max());
        auto Handler = [State = std::make_unique<int>(37), &Request, &CompletionSignal, &UserStrand, &ClientStream](boost::system::error_code Error) mutable
        {
            ++Request.Result.CompletionCount;
            Request.Result.RecordCompletion(
                static_cast<std::size_t>(*State), UserStrand.running_in_this_thread(),
                !ClientStream->IsIdle());
            Request.Result.RecordResult(Error);
            static_cast<void>(CompletionSignal.cancel());
        };
        ClientStream->async_write_shutdown(
            Net::bind_executor(UserStrand, std::move(Handler)));
        boost::system::error_code WaitError;
        co_await CompletionSignal.async_wait(
            Net::redirect_error(Net::use_awaitable, WaitError));
        EXPECT_EQ(WaitError, Net::error::operation_aborted);

        const std::array<std::byte, 1> Reply{std::byte{0x37}};
        const auto WriteResult = co_await ServerTransport->WriteSome(
            std::span<const std::byte>(Reply));
        EXPECT_EQ(WriteResult.Bytes, 1U);
        EXPECT_TRUE(WriteResult.Failure.Succeeded());
        std::array<std::byte, 1> Buffer{};
        const auto ReadResult = co_await ClientTransport->ReadSome(
            std::span<std::byte>(Buffer));
        EXPECT_EQ(ReadResult.Bytes, 1U);
        EXPECT_TRUE(ReadResult.Failure.Succeeded());
        EXPECT_EQ(Buffer[0], Reply[0]);

        EXPECT_TRUE(ClientTransport->Cancel().has_value());
        EXPECT_TRUE(ServerTransport->Cancel().has_value());
        EXPECT_TRUE(ClientTransport->Close().has_value());
        EXPECT_TRUE(ServerTransport->Close().has_value());
        EXPECT_TRUE((co_await ClientTransport->Activity()->Drain()).has_value());
        EXPECT_TRUE((co_await ServerTransport->Activity()->Drain()).has_value());
        EXPECT_TRUE((co_await Source->Activity()->Drain()).has_value());
        EXPECT_TRUE((co_await Destination->Activity()->Drain()).has_value());
    }

    /**
     * @brief 用无效 TLS record 触发真实 SSL read error 并观察异步完成生命周期。
     * @param Request 双端握手资源、执行器与结果观察槽。
     * @return 等待错误回调、carrier drain 及两端底层关闭完成的操作。
     */
    auto RunNativeTlsReadErrorScenario(NativeTlsReadErrorRequest Request)
        -> Net::awaitable<void>
    {
        auto Pair = Prism::Testing::MakeOwnedTransportPair(
            Request.RoundTrip.Ioc.get_executor());
        auto Source = std::move(Pair.FirstOwner);
        auto Destination = std::move(Pair.SecondOwner);
        auto ServerHandshake = [Destination, &Request]()
            -> Net::awaitable<Encrypted::SharedStream>
        {
            auto Handshake = co_await Encrypted::SslHandshake({
                Destination, Request.RoundTrip.ServerContext,
                std::chrono::steady_clock::now() + Encrypted::DefaultHandshakeTimeout,
                Prism::Testing::MakeTransportBytes()});
            EXPECT_EQ(Handshake.Failure.Code, Prism::Fault::Code::Success);
            co_return std::move(Handshake.Stream);
        };
        auto [ServerStream, ClientStream] = co_await (
            ServerHandshake() &&
            RunClientHandshake(Source, Request.RoundTrip.ClientContext));
        if (!ServerStream || !ClientStream)
        {
            EXPECT_TRUE(false) << "TLS handshake Failed";
            const auto SourceClose = co_await Prism::Testing::CloseFixture(Source);
            const auto DestinationClose = co_await Prism::Testing::CloseFixture(Destination);
            Request.Result.RawEndpointsDrained =
                SourceClose.Succeeded() && DestinationClose.Succeeded();
            co_return;
        }

        auto ClientActivity = ClientStream->Activity();
        auto ServerActivity = ServerStream->Activity();
        auto ClientWeak = std::weak_ptr<Prism::Transport::TlsStream>(ClientStream);
        auto UserStrand = Net::make_strand(Request.RoundTrip.Ioc.get_executor());
        Net::steady_timer CompletionSignal(Request.RoundTrip.Ioc);
        CompletionSignal.expires_at(std::chrono::steady_clock::time_point::max());
        std::array<std::byte, 1> Buffer{};
        ClientStream->async_read_some(
            Net::buffer(Buffer),
            Net::bind_executor(UserStrand,
                NativeTlsReadErrorCompletion<decltype(UserStrand)>{
                    Request.Result, UserStrand, ClientActivity, ClientWeak, CompletionSignal}));
        ClientStream.reset();

        const auto InvalidRecord = SvBytes("GARBAGE-not-a-Client-hello");
        const auto InputResult = co_await Destination->WriteSome(InvalidRecord);
        EXPECT_EQ(InputResult.Bytes, InvalidRecord.size());
        EXPECT_TRUE(InputResult.Failure.Succeeded());
        boost::system::error_code WaitError;
        co_await CompletionSignal.async_wait(
            Net::redirect_error(Net::use_awaitable, WaitError));
        EXPECT_EQ(WaitError, Net::error::operation_aborted);

        const auto ClientDrain = co_await ClientActivity->Drain();
        Request.Result.ClientActivityDrained =
            ClientDrain.has_value() && ClientActivity->IsRetired();
        Request.Result.CarrierRetiredAfterDrain = ClientWeak.expired();
        const auto ServerDrain = co_await ServerActivity->Drain();
        Request.Result.ServerActivityDrained =
            ServerDrain.has_value() && ServerActivity->IsRetired();
        ServerStream.reset();

        const auto SourceClose = co_await Prism::Testing::CloseFixture(Source);
        const auto DestinationClose = co_await Prism::Testing::CloseFixture(Destination);
        Request.Result.RawEndpointsDrained =
            SourceClose.Succeeded() && DestinationClose.Succeeded();
    }
} // namespace

TEST(PrismEncryptedDecorator, SslHandshakeNullInbound)
    {
        Net::io_context Ioc;
        Ssl::context Context(Ssl::context::tls_server);
        Encrypted::HandshakeResult Result;
        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Encrypted::SslHandshake({nullptr, Context, std::chrono::steady_clock::now() + Encrypted::DefaultHandshakeTimeout, Prism::Testing::MakeTransportBytes()});
                 });
        const auto Code = Result.Failure.Code;
        const auto &Stream = Result.Stream;
        const auto &Recovered = Result.Recovered;
        EXPECT_EQ(Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_EQ(Stream, nullptr);
        EXPECT_EQ(Recovered, nullptr);
    }

TEST(PrismEncryptedDecorator, HandshakeFailureRecoversTransport)
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
        EXPECT_NE(Code, Prism::Fault::Code::Success);
        EXPECT_EQ(Stream, nullptr);
        ASSERT_NE(Recovered, nullptr); // 失败后从 Connector 恢复底层传输
        EXPECT_EQ(Recovered->TransportType(), Prism::Transmission::Type::Tcp);
    }

TEST(PrismEncryptedDecorator, TlsRoundTripOverMemoryPipe)
    {
        Net::io_context Ioc;
        Ssl::context ServerContext(Ssl::context::tls_server);
        LoadSelfSignedCert(ServerContext);
        Ssl::context ClientContext(Ssl::context::tls_client);
        ClientContext.set_verify_mode(Ssl::verify_none);

        RunCoro(Ioc, RunTlsRoundTripScenario(
                         TlsRoundTripRequest{Ioc, ServerContext, ClientContext}));
    }

TEST(PrismEncryptedDecorator, WriteShutdownPreservesMoveOnlyCompletionHandler)
    {
        Net::io_context Ioc;
        Ssl::context Context(Ssl::context::tls_server);
        auto Pair = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto Stream = std::make_shared<Prism::Transport::TlsStream>(
            Prism::Transport::Connector(Pair.FirstOwner), Context);

        std::size_t CompletionCount = 0;
        boost::system::error_code CompletionError;
        Stream->async_write_shutdown([&](boost::system::error_code Error)
        {
            ++CompletionCount;
            CompletionError = Error;
        });
        Ioc.run();

        EXPECT_EQ(CompletionCount, 1U);
        const auto ExpectedError = boost::system::error_code(
            ERR_PACK(ERR_LIB_SSL, SSL_R_UNINITIALIZED),
            boost::asio::error::get_ssl_category());
        EXPECT_EQ(CompletionError, ExpectedError);

        auto Activity = Stream->Activity();
        RunCoro(Ioc, [Activity]() -> Net::awaitable<void>
        {
            EXPECT_TRUE((co_await Activity->Drain()).has_value());
        }());
        Prism::Testing::ExpectFixtureCloseReceipt(
            Prism::Testing::DriveClose(Ioc, Pair.FirstOwner));
        Prism::Testing::ExpectFixtureCloseReceipt(
            Prism::Testing::DriveClose(Ioc, Pair.SecondOwner));
    }

TEST(PrismEncryptedDecorator, WriteShutdownAcceptsMoveOnlyCompletionToken)
    {
        Net::io_context Ioc;
        Ssl::context ServerContext(Ssl::context::tls_server);
        LoadSelfSignedCert(ServerContext);
        Ssl::context ClientContext(Ssl::context::tls_client);
        ClientContext.set_verify_mode(Ssl::verify_none);
        MoveOnlyShutdownResult Result;
        RunCoro(Ioc, RunMoveOnlyShutdownScenario({
            TlsRoundTripRequest{Ioc, ServerContext, ClientContext}, Result}));

        EXPECT_EQ(Result.CompletionCount, 1U);
        EXPECT_TRUE(Result.Succeeded);
        EXPECT_EQ(Result.CapturedValue, 37U);
        EXPECT_TRUE(Result.OnAssociatedExecutor);
        EXPECT_TRUE(Result.OperationAliveDuringCallback);
    }

TEST(PrismEncryptedDecorator, NativeReadErrorUsesAssociatedExecutorAndRetainsCarrier)
{
    Net::io_context Ioc;
    Ssl::context ServerContext(Ssl::context::tls_server);
    LoadSelfSignedCert(ServerContext);
    Ssl::context ClientContext(Ssl::context::tls_client);
    ClientContext.set_verify_mode(Ssl::verify_none);
    NativeTlsReadErrorResult Result;

    RunCoro(Ioc, RunNativeTlsReadErrorScenario({
        TlsRoundTripRequest{Ioc, ServerContext, ClientContext}, Result}));

    EXPECT_EQ(Result.CompletionCount, 1U);
    EXPECT_TRUE(Result.Error);
    EXPECT_NE(Result.Error, Net::error::operation_aborted);
    EXPECT_EQ(Result.Bytes, 0U);
    EXPECT_TRUE(Result.OnAssociatedExecutor);
    EXPECT_TRUE(Result.OperationAliveDuringCallback);
    EXPECT_TRUE(Result.CarrierAliveDuringCallback);
    EXPECT_TRUE(Result.ClientActivityDrained);
    EXPECT_TRUE(Result.CarrierRetiredAfterDrain);
    EXPECT_TRUE(Result.ServerActivityDrained);
    EXPECT_TRUE(Result.RawEndpointsDrained);
}

TEST(PrismEncryptedDecorator, QueuedReadCancellationUsesAssociatedExecutor)
{
    Net::io_context Ioc;
    Ssl::context Context(Ssl::context::tls_server);
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
    auto Stream = std::make_shared<Prism::Transport::TlsStream>(
        Prism::Transport::Connector(Pair.FirstOwner), Context);
    auto UserStrand = Net::make_strand(Ioc.get_executor());
    Net::cancellation_signal Cancellation;
    std::array<std::byte, 1> Buffer{};
    std::size_t CompletionCount = 0;
    std::size_t CompletionBytes = 1;
    bool OnAssociatedExecutor = false;
    bool OperationAliveDuringCallback = false;
    boost::system::error_code CompletionError;

    Stream->async_read_some(Net::buffer(Buffer),
        Net::bind_cancellation_slot(Cancellation.slot(),
            Net::bind_executor(UserStrand, [&](boost::system::error_code Error, std::size_t Bytes)
            {
                ++CompletionCount;
                OnAssociatedExecutor = UserStrand.running_in_this_thread();
                OperationAliveDuringCallback = !Stream->IsIdle();
                CompletionError = Error;
                CompletionBytes = Bytes;
            })));
    Cancellation.emit(Net::cancellation_type::all);
    Ioc.run();

    EXPECT_EQ(CompletionCount, 1U);
    EXPECT_EQ(CompletionBytes, 0U);
    EXPECT_TRUE(OnAssociatedExecutor);
    EXPECT_TRUE(OperationAliveDuringCallback);
    EXPECT_EQ(CompletionError, Net::error::operation_aborted);
    EXPECT_TRUE(Stream->IsIdle());
    Prism::Testing::ExpectFixtureCloseReceipt(
        Prism::Testing::DriveClose(Ioc, Pair.FirstOwner));
    Prism::Testing::ExpectFixtureCloseReceipt(
        Prism::Testing::DriveClose(Ioc, Pair.SecondOwner));
}

TEST(PrismEncryptedDecorator, UnownedFacadeFailureUsesAssociatedExecutor)
{
    Net::io_context Ioc;
    Ssl::context Context(Ssl::context::tls_server);
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
    Prism::Transport::TlsStream Stream(
        Prism::Transport::Connector(Pair.FirstOwner), Context);
    auto UserStrand = Net::make_strand(Ioc.get_executor());
    std::array<std::byte, 1> Buffer{};
    std::size_t CompletionCount = 0;
    std::size_t CompletionBytes = 1;
    bool OnAssociatedExecutor = false;
    boost::system::error_code CompletionError;

    Stream.async_read_some(Net::buffer(Buffer),
        Net::bind_executor(UserStrand,
            [&](boost::system::error_code Error, std::size_t Bytes)
            {
                ++CompletionCount;
                OnAssociatedExecutor = UserStrand.running_in_this_thread();
                CompletionError = Error;
                CompletionBytes = Bytes;
            }));
    Ioc.run();

    EXPECT_EQ(CompletionCount, 1U);
    EXPECT_EQ(CompletionBytes, 0U);
    EXPECT_TRUE(OnAssociatedExecutor);
    EXPECT_EQ(CompletionError,
        boost::system::make_error_code(Prism::Fault::Code::InvalidArgument));
    Prism::Testing::ExpectFixtureCloseReceipt(
        Prism::Testing::DriveClose(Ioc, Pair.FirstOwner));
    Prism::Testing::ExpectFixtureCloseReceipt(
        Prism::Testing::DriveClose(Ioc, Pair.SecondOwner));
}

TEST(PrismEncryptedDecorator, ControlReservationRejectionUsesAssociatedExecutor)
{
    constexpr std::size_t AcceptedControlCount = 65;
    Net::io_context Ioc;
    Ssl::context Context(Ssl::context::tls_server);
    auto Pair = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
    auto Stream = std::make_shared<Prism::Transport::TlsStream>(
        Prism::Transport::Connector(Pair.FirstOwner), Context);
    auto UserStrand = Net::make_strand(Ioc.get_executor());
    std::array<Net::cancellation_signal, AcceptedControlCount> Cancellations;
    std::size_t CanceledCount = 0;
    std::size_t InvalidCanceledResultCount = 0;
    bool AllCanceledOnAssociatedExecutor = true;
    std::size_t RejectedCount = 0;
    bool RejectedOnAssociatedExecutor = false;
    boost::system::error_code RejectedError;

    for (std::size_t Index = 0; Index < AcceptedControlCount; ++Index)
    {
        Stream->async_write_shutdown(
            Net::bind_cancellation_slot(Cancellations[Index].slot(),
                Net::bind_executor(UserStrand, [&](auto Error)
                {
                    ++CanceledCount;
                    AllCanceledOnAssociatedExecutor =
                        AllCanceledOnAssociatedExecutor && UserStrand.running_in_this_thread();
                    if (Error != Net::error::operation_aborted)
                        ++InvalidCanceledResultCount;
                })));
    }
    Stream->async_write_shutdown(Net::bind_executor(UserStrand,
        [&](auto Error)
        {
            ++RejectedCount;
            RejectedOnAssociatedExecutor = UserStrand.running_in_this_thread();
            RejectedError = Error;
        }));
    for (auto& Cancellation : Cancellations)
        Cancellation.emit(Net::cancellation_type::all);
    Ioc.run();

    EXPECT_EQ(CanceledCount, AcceptedControlCount);
    EXPECT_EQ(InvalidCanceledResultCount, 0U);
    EXPECT_TRUE(AllCanceledOnAssociatedExecutor);
    EXPECT_EQ(RejectedCount, 1U);
    EXPECT_TRUE(RejectedOnAssociatedExecutor);
    EXPECT_EQ(RejectedError,
        boost::system::make_error_code(Prism::Fault::Code::ResourceUnavailable));
    EXPECT_TRUE(Stream->IsIdle());
    Prism::Testing::ExpectFixtureCloseReceipt(
        Prism::Testing::DriveClose(Ioc, Pair.FirstOwner));
    Prism::Testing::ExpectFixtureCloseReceipt(
        Prism::Testing::DriveClose(Ioc, Pair.SecondOwner));
}

TEST(PrismEncryptedDecorator, AccessorsAndRelease)
    {
        Net::io_context Ioc;
        Ssl::context Context(Ssl::context::tls_server);

        auto MemoryPair11 = Prism::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair11.FirstOwner;
        auto& Remote = *MemoryPair11.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        Prism::Transport::Connector Connector(Source);
        auto Stream = std::make_shared<Encrypted::StreamType>(
            std::move(Connector), Context);

        auto Transport = std::make_shared<Encrypted>(Stream, Prism::Testing::MakeTransportBytes());
        EXPECT_EQ(Transport->TransportType(), Prism::Transmission::Type::Tcp);
        EXPECT_NE(Transport->NextLayer(), nullptr);
        EXPECT_EQ(Transport->Stream().native_handle(), Stream->native_handle());
        EXPECT_NO_THROW((void)Transport->Executor());

        // Close/Cancel（未握手流上安全）
        Prism::Transmission::ControlResult CancelResult;
        EXPECT_NO_THROW(CancelResult = Transport->Cancel());
        EXPECT_TRUE(CancelResult.has_value());
        Prism::Transmission::ControlResult CloseResult;
        EXPECT_NO_THROW(CloseResult = Transport->Close());
        EXPECT_TRUE(CloseResult.has_value());
        Ioc.run();
        EXPECT_TRUE(Prism::Testing::DriveDrain(Ioc, Transport).has_value());
        auto Released = Transport->ReleaseStream();
        EXPECT_EQ(Released.value().get(), Stream.get());
        EXPECT_TRUE(Prism::Testing::DriveDrain(Ioc, Source).has_value());
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, MemoryPair11.SecondOwner));
    }
