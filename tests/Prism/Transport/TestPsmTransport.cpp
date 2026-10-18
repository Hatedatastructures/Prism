/**
 * @file TestPsmTransport.cpp
 * @brief Prism::Transport 系测试库组件深度测试
 * @details 覆盖 Prism::Transport::Transmission 抽象基类全部方法
 *          （Prefix / TransportType / completion-handler 桥接 /
 *          NextLayer / lowest_layer）与 AsyncWrite / AsyncRead
 *          自由函数的错误路径，传输层的空操作方法与
 *          Cancel / SetTimeout，Reliable / Unreliable
 *          的真实 socket 收发，以及 Middleware Dial / relay 的
 *          Name() 访问器。
 */

#include <boost/asio/co_spawn.hpp>
#include "TransportResources.hpp"
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Unreliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;


    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Ioc.restart();
        Net::co_spawn(Ioc, std::move(Coro),
                      [&](std::exception_ptr Error)
                      {
                          Exception = Error;
                      });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    using AcceptCompletion = Net::experimental::channel<void(boost::system::error_code)>;

    struct SocketAcceptState final
    {
        std::exception_ptr Failure;
        std::shared_ptr<AcceptCompletion> Done;
    };

    auto StartSocketAccept(
        Net::ip::tcp::acceptor &Acceptor,
        Prism::Transport::Reliable &ServerSocket) -> std::shared_ptr<SocketAcceptState>
    {
        const auto State = std::make_shared<SocketAcceptState>();
        State->Done = std::make_shared<AcceptCompletion>(Acceptor.get_executor(), 1);
        Net::co_spawn(
            Acceptor.get_executor(),
            [&Acceptor, &ServerSocket]() -> Net::awaitable<void>
            {
                co_await Acceptor.async_accept(ServerSocket.NativeSocket(), Net::use_awaitable);
            },
            [State](std::exception_ptr Error)
            {
                State->Failure = Error;
                (void)State->Done->try_send(boost::system::error_code{});
            });
        return State;
    }

    auto WaitSocketAccept(const std::shared_ptr<SocketAcceptState> &State)
        -> Net::awaitable<bool>
    {
        co_await State->Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(State->Failure);
        co_return !State->Failure;
    }

    auto RunSocketLoopbackScenario(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto TransportOwner59 = std::make_shared<Prism::Transport::Reliable>(Ioc.get_executor());
        auto& ServerSocket = *TransportOwner59;
        auto TransportOwner58 = std::make_shared<Prism::Transport::Reliable>(Ioc.get_executor());
        auto& ClientSocket = *TransportOwner58;
        const auto AcceptorEndpoint =
            Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), 0);
        Net::ip::tcp::acceptor Acceptor(Ioc.get_executor(), AcceptorEndpoint);
        const auto Endpoint = Acceptor.local_endpoint();
        const auto Accept = StartSocketAccept(Acceptor, ServerSocket);
        const auto ConnectError = co_await ClientSocket.Connect(Endpoint);
        EXPECT_TRUE(ConnectError.has_value());
        if (!ConnectError)
        {
            boost::system::error_code CloseError;
            Acceptor.close(CloseError);
            co_await WaitSocketAccept(Accept);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner58);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        if (!co_await WaitSocketAccept(Accept))
        {
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner58);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        EXPECT_TRUE(ClientSocket.IsOpen());
        const std::string_view Message = "ping";
        Prism::Fault::Failure WriteError;
        ([&](Prism::IoResult Result) { WriteError = Result.Failure; return Result.Bytes; })(co_await ClientSocket.WriteSome(Prism::AsBytesSpan(Message)));
        EXPECT_TRUE(WriteError.Succeeded());
        std::array<std::byte, 8> Buffer{};
        Prism::Fault::Failure ReadError;
        const auto Count = ([&](Prism::IoResult Result) { ReadError = Result.Failure; return Result.Bytes; })(co_await ServerSocket.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), Count), "ping");
        const auto ShutdownReceipt = co_await ClientSocket.WriteShutdown();
        EXPECT_TRUE(ShutdownReceipt.has_value());
        const auto CancelResult = ClientSocket.Cancel();
        EXPECT_TRUE(CancelResult.has_value());
        const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner58);
        const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner59);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
    }

    auto RunUdpLoopbackScenario(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto TransportOwner57 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Client = *TransportOwner57;
        auto TransportOwner56 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Server = *TransportOwner56;
        boost::system::error_code OpenError;
        Server.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Open Failed: " << OpenError.message();
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner56);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner57);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        if (!Server.Bind(0))
        {
            EXPECT_TRUE(false) << "Bind Failed";
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner56);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner57);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        Client.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Client Open Failed";
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner56);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner57);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        const auto LocalEndpoint = Server.NativeSocket().local_endpoint();
        auto LocalAddress = LocalEndpoint.address().to_string();
        if (LocalEndpoint.address().is_unspecified())
        {
            LocalAddress = "127.0.0.1";
        }
        if (!Client.Connect(LocalAddress + ":" + std::to_string(LocalEndpoint.port())))
        {
            EXPECT_TRUE(false) << "Connect Failed";
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner56);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner57);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        const std::string_view Message = "udp!";
        Prism::Fault::Failure ErrorCode;
        const auto Written = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Client.WriteSome(Prism::AsBytes(Prism::AsU8Span(Message))));
        EXPECT_EQ(Written, 4u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        std::array<std::byte, 16> Buffer{};
        const auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 4u);
        EXPECT_EQ(static_cast<char>(Buffer[0]), 'u');
        const auto CancelResult = Server.Cancel();
        EXPECT_TRUE(CancelResult.has_value());
        const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner56);
        const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner57);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
    }

    /**
     * @brief Prism::Transport::Transmission 测试替身（叶子节点）
     */
    class MockTransport final : public Prism::Transmission
    {
    public:
        explicit MockTransport(Net::any_io_executor Executor,
                               std::error_code ReadError = {}, std::size_t ReadCount = 0)
            : Prism::Transmission(Executor), Ex_(std::move(Executor)), ReadEc_(ReadError), ReadN_(ReadCount)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            OperationFailure = ReadEc_;
            { std::move(Handler)(Prism::IoResult{ReadN_, Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            if (WriteCalls_++ == 0 && WriteFirstOk_)
            {
                OperationFailure.clear();
                { std::move(Handler)(Prism::IoResult{WriteN_, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            OperationFailure = WriteEc_;
            { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto OnClose() -> ControlResult override
        {

            return {};
        }

        auto OnCancel() -> ControlResult override
        {

            return {};
        }
        std::error_code WriteEc_{};
        std::size_t WriteN_{0};
        bool WriteFirstOk_{false};
        std::size_t WriteCalls_{0};

    private:
        Net::any_io_executor Ex_;
        std::error_code ReadEc_;
        std::size_t ReadN_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }
    };

    TEST(PsmTransmission, BasicAccessors)
    {
        Net::io_context Loop;
        auto TransportOwner55 = std::make_shared<MockTransport>(Loop.get_executor());
        auto& TransportObject = *TransportOwner55;

        // 叶子节点 TransportType → Tcp
        EXPECT_EQ(TransportObject.TransportType(), Prism::Transmission::Type::Tcp);
        EXPECT_EQ(TransportObject.NextLayer(), nullptr);
        const auto *ConstTransport = &TransportObject;
        EXPECT_EQ(ConstTransport->NextLayer(), nullptr);
        EXPECT_EQ(TransportObject.get_executor(), TransportObject.Executor());
        EXPECT_EQ(TransportObject.lowest_layer<MockTransport>(), &TransportObject);
        EXPECT_EQ(ConstTransport->lowest_layer<const MockTransport>(), ConstTransport);
        EXPECT_EQ(TransportObject.lowest_layer<Net::io_context>(), nullptr);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner55));

    }

    TEST(PsmTransmission, DelegatedTransportType)
    {
        Net::io_context Loop;
        // 子节点覆写 TransportType 返回 udp，验证委托路径
        struct UdpLike final : public Prism::Transmission
        {
            explicit UdpLike(Net::any_io_executor Executor) : Prism::Transmission(Executor), Ex_(std::move(Executor))
            {
            }
            [[nodiscard]] auto TransportType() const noexcept -> Type override
            {
                return Type::Udp;
            }
            [[nodiscard]] auto Executor() const -> ExecutorType override
            {
                return Ex_;
            }
            auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            auto OnClose() -> ControlResult override
        {

            return {};
        }
            auto OnCancel() -> ControlResult override
        {

            return {};
        }
            Net::any_io_executor Ex_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }
    };
        auto TransportOwner54 = std::make_shared<UdpLike>(Loop.get_executor());
        auto& Leaf = *TransportOwner54;
        EXPECT_EQ(Leaf.TransportType(), Prism::Transmission::Type::Udp);

        // 装饰器：NextLayer 非空 → 委托
        struct Wrapper final : public Prism::Transmission
        {
            explicit Wrapper(Prism::Transmission *Inner) : Prism::Transmission(Inner->Executor()), Next_(Inner)
            {
            }
            [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
            {
                return Next_;
            }
            [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
            {
                return Next_;
            }
            [[nodiscard]] auto Executor() const -> ExecutorType override
            {
                return Next_->Executor();
            }
            auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            auto OnClose() -> ControlResult override
        {

            return {};
        }
            auto OnCancel() -> ControlResult override
        {

            return {};
        }
            Prism::Transmission *Next_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }
    };
        auto TransportOwner53 = std::make_shared<Wrapper>(&Leaf);
        auto& Wrapped = *TransportOwner53;
        EXPECT_EQ(Wrapped.TransportType(), Prism::Transmission::Type::Udp);
        EXPECT_EQ(Wrapped.lowest_layer<UdpLike>(), &Leaf);
        EXPECT_EQ(Wrapped.NextLayer(), &Leaf);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner53));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner54));
    }

    TEST(PsmTransmission, CompletionHandlerBridges)
    {
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransport>(
            Loop.get_executor(), std::make_error_code(std::errc::io_error), 0);

        // completion-handler 风格读（默认 co_spawn 桥接）
        std::promise<Prism::IoResult> DoneR;
        auto ReadFuture = DoneR.get_future();
        TransportObject->ReadSome(std::span<std::byte>{}, [&](Prism::IoResult Result)
                          { DoneR.set_value(Result); });
        Loop.run();
        const auto ReadResult = ReadFuture.get();
        EXPECT_EQ(ReadResult.Bytes, 0u);

        // completion-handler 风格写（独立 io_context）
        Net::io_context Ioc2;
        auto SecondTransport = std::make_shared<MockTransport>(Ioc2.get_executor());
        std::promise<Prism::IoResult> DoneW;
        auto WriteFuture = DoneW.get_future();
        std::array<std::byte, 4> IoBuffer{};
        SecondTransport->WriteSome(std::span<const std::byte>(IoBuffer), [&](Prism::IoResult Result)
                            { DoneW.set_value(Result); });
        Ioc2.run();
        (void)WriteFuture.get();
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportObject));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc2, SecondTransport));
    }

    TEST(PsmTransmission, FreeAsyncWriteRead)
    {
        Net::io_context Loop;
        std::array<std::byte, 8> IoBuffer{};
        Prism::Fault::Failure OperationFailure;

        // AsyncWrite：单次写满
        auto TransportOwner52 = std::make_shared<MockTransport>(Loop.get_executor());
        auto& Ok = *TransportOwner52;
        Ok.WriteFirstOk_ = true;
        Ok.WriteN_ = 8;
        RunCoro(Loop,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Ok.WriteExact(std::span<const std::byte>(IoBuffer)));
                     EXPECT_EQ(ByteCount, 8u);
                     EXPECT_TRUE(OperationFailure.Succeeded());
                 });

        // AsyncWrite：部分写入后错误中断
        auto TransportOwner51 = std::make_shared<MockTransport>(Loop.get_executor());
        auto& ErrorCarrier = *TransportOwner51;
        ErrorCarrier.WriteFirstOk_ = true;
        ErrorCarrier.WriteN_ = 4;
        ErrorCarrier.WriteEc_ = std::make_error_code(std::errc::io_error);
        RunCoro(Loop,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await ErrorCarrier.WriteExact(std::span<const std::byte>(IoBuffer)));
                     EXPECT_EQ(ByteCount, 4u);
                     EXPECT_TRUE(OperationFailure.Failed());
                 });

        // AsyncWrite：n==0 表示对端关闭 → broken_pipe
        OperationFailure = {};
        auto TransportOwner50 = std::make_shared<MockTransport>(Loop.get_executor());
        auto& ZeroCarrier = *TransportOwner50;
        ZeroCarrier.WriteN_ = 0;
        RunCoro(Loop,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await ZeroCarrier.WriteExact(std::span<const std::byte>(IoBuffer)));
                     EXPECT_EQ(ByteCount, 0u);
                     EXPECT_TRUE(OperationFailure.Failed());
                 });

        // AsyncRead：错误中断
        auto TransportOwner49 = std::make_shared<MockTransport>(Loop.get_executor(), std::make_error_code(std::errc::io_error), 0);
        auto& ReadErrorCarrier = *TransportOwner49;
        RunCoro(Loop,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await ReadErrorCarrier.ReadExact(std::span<std::byte>(IoBuffer)));
                     EXPECT_EQ(ByteCount, 0u);
                     EXPECT_TRUE(OperationFailure.Failed());
                 });
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner49));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner50));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner51));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner52));
    }

    TEST(PsmTransmission, ToEcBranches)
    {
        // 空错误码 → 空 boost ec（经 completion-handler 桥接触发 ToEc）
        {
            Net::io_context Loop;
            auto Ok = std::make_shared<MockTransport>(Loop.get_executor());
            std::promise<Prism::Fault::Failure> Done1;
            auto F1 = Done1.get_future();
            Ok->ReadSome(std::span<std::byte>{}, [&](Prism::IoResult Result)
                               { Done1.set_value(Result.Failure); });
            Loop.run();
            EXPECT_TRUE(F1.get().Succeeded());
            Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, Ok));
        }

        // fault 分类错误 → boost 协议分类（Fault::Category() 匹配）
        {
            Net::io_context Loop;
            const auto FaultEc = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
            auto FaultCarrier = std::make_shared<MockTransport>(Loop.get_executor(), FaultEc, 0);
            std::promise<Prism::Fault::Failure> Done2;
            auto F2 = Done2.get_future();
            FaultCarrier->ReadSome(std::span<std::byte>{}, [&](Prism::IoResult Result)
                               { Done2.set_value(Result.Failure); });
            Loop.run();
            EXPECT_TRUE(F2.get().Failed());
            Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, FaultCarrier));
        }

        // generic 分类错误 → generic boost ec
        {
            Net::io_context Loop;
            const auto GenEc = std::make_error_code(std::errc::connection_reset);
            auto GenericCarrier = std::make_shared<MockTransport>(Loop.get_executor(), GenEc, 0);
            std::promise<Prism::Fault::Failure> Done3;
            auto F3 = Done3.get_future();
            GenericCarrier->ReadSome(std::span<std::byte>{}, [&](Prism::IoResult Result)
                               { Done3.set_value(Result.Failure); });
            Loop.run();
            EXPECT_EQ(F3.get().Native, GenEc);
            Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, GenericCarrier));
        }
    }

TEST(SocketStream, LoopbackTransfer)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunSocketLoopbackScenario(Ioc));
    }

TEST(UdpTransmission, LoopbackDatagram)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunUdpLoopbackScenario(Ioc));
    }

    TEST(UdpTransmission, ConnectRejectsMalformedHostPort)
    {
        Net::io_context Loop;
        const std::array<std::string_view, 9> Invalid{
            "", ":443", "example.com:", "example.com:not-a-port", "example.com:1x",
            "example.com:65536", "[::1", "[::1]443", "2001:db8::1:443"};

        for (const auto Remote : Invalid)
        {
            auto TransportOwner48 = std::make_shared<Prism::Transport::Unreliable>(Loop.get_executor());
            auto& Transport = *TransportOwner48;
            EXPECT_FALSE(Transport.Connect(std::string(Remote))) << Remote;
            Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner48));
        }
    }

    TEST(UdpTransmission, ConnectAcceptsIpv4Ipv6AndDomain)
    {
        Net::io_context Loop;
        const std::array<std::string_view, 3> Valid{
            "127.0.0.1:443", "[::1]:443", "example.com:443"};

        for (const auto Remote : Valid)
        {
            auto TransportOwner47 = std::make_shared<Prism::Transport::Unreliable>(Loop.get_executor());
            auto& Transport = *TransportOwner47;
            EXPECT_TRUE(Transport.Connect(std::string(Remote))) << Remote;
            Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner47));
        }
    }

    TEST(MiddlewareNames, Accessors)
    {
        Prism::Middleware::Builtin::DialMiddleware Dial;
        EXPECT_EQ(Dial.Name(), "Dial");
        Prism::Middleware::Builtin::RelayMiddleware Relay(nullptr);
        EXPECT_EQ(Relay.Name(), "relay");
    }

} // namespace
