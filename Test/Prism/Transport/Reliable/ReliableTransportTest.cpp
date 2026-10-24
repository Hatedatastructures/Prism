/**
 * @file ReliableTransportTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "../Core/TransportDecoratorSupport.hpp"
#include "../Core/TransportResources.hpp"

#include <boost/asio/experimental/channel.hpp>

namespace
{
    using AcceptCompletion = Net::experimental::channel<void(boost::system::error_code)>;

    struct TcpAcceptState final
    {
        std::shared_ptr<Prism::Transport::Reliable> Server;
        std::exception_ptr Failure;
        std::shared_ptr<AcceptCompletion> Done;
    };

    auto StartTcpAccept(Net::ip::tcp::acceptor &Acceptor)
        -> std::shared_ptr<TcpAcceptState>
    {
        const auto State = std::make_shared<TcpAcceptState>();
        State->Done = std::make_shared<AcceptCompletion>(Acceptor.get_executor(), 1);
        Net::co_spawn(
            Acceptor.get_executor(),
            [&Acceptor, State]() -> Net::awaitable<void>
            {
                auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
                State->Server = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
            },
            [State](std::exception_ptr Error)
            {
                State->Failure = Error;
                (void)State->Done->try_send(boost::system::error_code{});
            });
        return State;
    }

    auto WaitTcpAccept(const std::shared_ptr<TcpAcceptState> &State) -> Net::awaitable<bool>
    {
        co_await State->Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(State->Failure);
        co_return !State->Failure && State->Server != nullptr;
    }

    auto RunReliableLoopbackReadWrite(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        Net::ip::tcp::acceptor Acceptor(IoContext, {Net::ip::tcp::v4(), 0});
        const auto Endpoint = Acceptor.local_endpoint();
        const auto ConnectEndpoint = Net::ip::tcp::endpoint(
            Net::ip::address_v4::loopback(), Endpoint.port());
        auto TransportOwner46 = std::make_shared<Prism::Transport::Reliable>(IoContext.get_executor());
        auto& Client = *TransportOwner46;
        boost::system::error_code OpenError;
        Client.NativeSocket().open(Net::ip::tcp::v4(), OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Open Failed: " << OpenError.message();
            const auto CloseReceipt46 = co_await Prism::Testing::CloseFixture(TransportOwner46);
            Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt46);
            co_return;
        }
        const auto Accept = StartTcpAccept(Acceptor);
        auto &Server = Accept->Server;
        co_await Client.NativeSocket().async_connect(ConnectEndpoint, Net::use_awaitable);
        if (!co_await WaitTcpAccept(Accept))
        {
            EXPECT_TRUE(false) << "Accept Failed";
            const auto CloseReceipt46 = co_await Prism::Testing::CloseFixture(TransportOwner46);
            Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt46);
            co_return;
        }
        Prism::Fault::Failure ErrorCode;
        const auto Written = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Client.WriteExact(SvBytes("hello")));
        EXPECT_EQ(Written, 5u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        std::array<std::byte, 8> Buffer{};
        const auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 5u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(5))), "hello");
        const auto ReverseWritten = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server->WriteExact(SvBytes("xyz")));
        EXPECT_EQ(ReverseWritten, 3u);
        const auto ReverseRead = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Client.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReverseRead, 3u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(3))), "xyz");
        const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner46);
        const auto ServerReceipt = co_await Prism::Testing::CloseFixture(Server);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
    }

    auto RunReliableReadEof(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        Net::ip::tcp::acceptor Acceptor(IoContext, {Net::ip::tcp::v4(), 0});
        const auto Endpoint = Acceptor.local_endpoint();
        const auto ConnectEndpoint = Net::ip::tcp::endpoint(
            Net::ip::address_v4::loopback(), Endpoint.port());
        auto TransportOwner45 = std::make_shared<Prism::Transport::Reliable>(IoContext.get_executor());
        auto& Client = *TransportOwner45;
        boost::system::error_code OpenError;
        Client.NativeSocket().open(Net::ip::tcp::v4(), OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Open Failed: " << OpenError.message();
            const auto CloseReceipt45 = co_await Prism::Testing::CloseFixture(TransportOwner45);
            Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt45);
            co_return;
        }
        const auto Accept = StartTcpAccept(Acceptor);
        auto &Server = Accept->Server;
        co_await Client.NativeSocket().async_connect(ConnectEndpoint, Net::use_awaitable);
        if (!co_await WaitTcpAccept(Accept))
        {
            EXPECT_TRUE(false) << "Accept Failed";
            const auto CloseReceipt45 = co_await Prism::Testing::CloseFixture(TransportOwner45);
            Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt45);
            co_return;
        }
        const auto ShutdownReceipt = co_await Client.WriteShutdown();
        EXPECT_TRUE(ShutdownReceipt.has_value());
        std::array<std::byte, 8> Buffer{};
        Prism::Fault::Failure ErrorCode;
        const auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server->ReadExact(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 0u);
        EXPECT_EQ(ErrorCode.Code, Prism::Fault::Code::Eof);
        const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner45);
        const auto ServerReceipt = co_await Prism::Testing::CloseFixture(Server);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
    }

    auto RunReliableBrokenPipe(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        Net::ip::tcp::acceptor Acceptor(IoContext, {Net::ip::tcp::v4(), 0});
        const auto Endpoint = Acceptor.local_endpoint();
        const auto ConnectEndpoint = Net::ip::tcp::endpoint(
            Net::ip::address_v4::loopback(), Endpoint.port());
        auto TransportOwner44 = std::make_shared<Prism::Transport::Reliable>(IoContext.get_executor());
        auto& Client = *TransportOwner44;
        boost::system::error_code OpenError;
        Client.NativeSocket().open(Net::ip::tcp::v4(), OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Open Failed: " << OpenError.message();
            const auto CloseReceipt44 = co_await Prism::Testing::CloseFixture(TransportOwner44);
            Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt44);
            co_return;
        }
        const auto Accept = StartTcpAccept(Acceptor);
        auto &Server = Accept->Server;
        co_await Client.NativeSocket().async_connect(ConnectEndpoint, Net::use_awaitable);
        if (!co_await WaitTcpAccept(Accept))
        {
            EXPECT_TRUE(false) << "Accept Failed";
            const auto CloseReceipt44 = co_await Prism::Testing::CloseFixture(TransportOwner44);
            Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt44);
            co_return;
        }
        const auto ShutdownReceipt = co_await Server->WriteShutdown();
        EXPECT_TRUE(ShutdownReceipt.has_value());
        const auto ServerClose = Server->Close();
        std::array<std::byte, 8> Buffer{};
        Prism::Fault::Failure ErrorCode;
        const auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Client.ReadExact(std::span<std::byte>(Buffer)));
        EXPECT_TRUE(ReadCount == 0u || ErrorCode.Failed()) << "对端关闭后读应返回 EOF 或错误";
        bool Failed = false;
        Prism::Fault::Failure WriteError;
        for (int Attempt = 0; Attempt < 20 && !Failed; ++Attempt)
        {
            const auto Written = ([&](Prism::IoResult Result) { WriteError = Result.Failure; return Result.Bytes; })(co_await Client.WriteExact(SvBytes("Data")));
            if (WriteError.Failed() || Written == 0)
            {
                Failed = true;
            }
        }
        EXPECT_TRUE(Failed) << "对端关闭后写入应失败";
        const auto ServerDrain = co_await Server->Activity()->Drain();
        EXPECT_TRUE(ServerClose.has_value());
        EXPECT_TRUE(ServerDrain.has_value());
        const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner44);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
    }
} // namespace

TEST(Reliable, LoopbackReadWriteFull)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunReliableLoopbackReadWrite(Ioc));
    }


TEST(Reliable, ReadEofOnShutdown)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunReliableReadEof(Ioc));
    }


TEST(Reliable, BrokenPipeOnPeerClose)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunReliableBrokenPipe(Ioc));
    }


TEST(Reliable, ErrorInterruptReturnsPartial)
    {
        // 组合操作：先读 3 字节，再遇错误 → 返回已读字节
        Net::io_context Loop;
        auto Mock = std::make_shared<ProgrammableMock>(Loop.get_executor());
        Mock->ReadFirstN_ = 3;
        Mock->ReadEc_ = std::make_error_code(std::errc::io_error);

        Prism::Fault::Failure OperationFailure;
        std::size_t ReceivedCount = 0;
        Net::co_spawn(
            Loop,
                 [&]() -> Net::awaitable<void>
            {
                std::array<std::byte, 8> IoBuffer{};
                ReceivedCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Mock->ReadExact(std::span<std::byte>(IoBuffer)));
            },
            Net::detached);
        Loop.run();
        EXPECT_EQ(ReceivedCount, 3u);
        EXPECT_TRUE(OperationFailure.Failed());
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, Mock));
    }

TEST(Reliable, WriteZeroMeansBrokenPipe)
    {
        // 完整写收到零进度成功时明确返回 WouldBlock，不能猜测原生 broken_pipe。
        Net::io_context Loop;
        auto Mock = std::make_shared<ProgrammableMock>(Loop.get_executor());
        Mock->WriteN_ = 0;

        Prism::Fault::Failure OperationFailure;
        std::size_t ReceivedCount = 0;
        Net::co_spawn(
            Loop,
                 [&]() -> Net::awaitable<void>
            {
                std::array<std::byte, 8> IoBuffer{};
                ReceivedCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Mock->WriteExact(std::span<const std::byte>(IoBuffer)));
            },
            Net::detached);
        Loop.run();
        EXPECT_EQ(ReceivedCount, 0u);
        ASSERT_TRUE(OperationFailure.Failed());
        EXPECT_EQ(OperationFailure.Code, Prism::Fault::Code::WouldBlock);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, Mock));
    }

TEST(Reliable, AccessorsAndRelease)
    {
        Net::io_context Loop;
        auto TransportOwner43 = std::make_shared<Prism::Transport::Reliable>(Loop.get_executor());
        auto& TransportObject = *TransportOwner43;

        EXPECT_EQ(TransportObject.TransportType(), Prism::Transmission::Type::Tcp);
        EXPECT_EQ(TransportObject.NextLayer(), nullptr);
        EXPECT_EQ(TransportObject.lowest_layer<Prism::Transport::Reliable>(), &TransportObject);
        EXPECT_NO_THROW((void)TransportObject.Executor());

        // 构造后 socket 未打开：Release 返回未打开的 socket
        auto Sock = TransportObject.ReleaseSocket();
        ASSERT_TRUE(Sock.has_value());
        EXPECT_FALSE(Sock->is_open());
        // 二次 Release：无 socket → nullopt
        EXPECT_FALSE(TransportObject.ReleaseSocket().has_value());

        auto TransportOwner42 = std::make_shared<Prism::Transport::Reliable>(Loop.get_executor());
        auto& SecondTransport = *TransportOwner42;
        Prism::Transmission::ControlResult CloseResult;
        EXPECT_NO_THROW(CloseResult = SecondTransport.Close());
        EXPECT_TRUE(CloseResult.has_value());
        Prism::Transmission::ControlResult CancelResult;
        EXPECT_NO_THROW(CancelResult = SecondTransport.Cancel());
        EXPECT_TRUE(CancelResult.has_value());
        Loop.run();
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, TransportOwner42).has_value());
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner43));
    }
