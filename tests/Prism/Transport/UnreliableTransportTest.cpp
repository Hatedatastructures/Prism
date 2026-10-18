/**
 * @file UnreliableTransportTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "TransportDecoratorTestSupport.hpp"
#include "TransportResources.hpp"

namespace
{
    auto RunUnreliableDatagramRoundTrip(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto TransportOwner98 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Server = *TransportOwner98;
        auto TransportOwner97 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Client = *TransportOwner97;
        boost::system::error_code OpenError;
        Server.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        Server.NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Server Open/Bind Failed: " << OpenError.message();
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner98);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner97);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        Client.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        Client.NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Client Open/Bind Failed: " << OpenError.message();
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner98);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner97);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        Client.SetRemote(Server.NativeSocket().local_endpoint());
        EXPECT_TRUE(Client.RemoteEndpoint().has_value());
        Prism::Fault::Failure ErrorCode;
        const auto Written = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Client.WriteSome(SvBytes("ping")));
        EXPECT_EQ(Written, 4u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        std::array<std::byte, 16> Buffer{};
        auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 4u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(4))), "ping");
        EXPECT_TRUE(Server.RemoteEndpoint().has_value());
        const auto ReverseWritten = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server.WriteSome(SvBytes("pong")));
        EXPECT_EQ(ReverseWritten, 4u);
        ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Client.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 4u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(4))), "pong");
        const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner98);
        const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner97);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
    }

    auto RunWriteWithoutRemote(
        Prism::Transport::Unreliable &Transport,
        Prism::Fault::Failure &ErrorCode) -> Net::awaitable<void>
    {
        const auto Result = co_await Transport.WriteSome(SvBytes("nope")); ErrorCode = Result.Failure; const auto Count = Result.Bytes;
        EXPECT_EQ(Count, 0u);
    }

    auto RunSourceFiltering(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto TransportOwner96 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Server = *TransportOwner96;
        auto TransportOwner95 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& ClientA = *TransportOwner95;
        auto TransportOwner94 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& ClientB = *TransportOwner94;
        boost::system::error_code OpenError;
        Server.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        Server.NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenError);
        ClientA.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        ClientA.NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenError);
        ClientB.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        ClientB.NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Open/Bind Failed: " << OpenError.message();
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner96);
            const auto FirstReceipt = co_await Prism::Testing::CloseFixture(TransportOwner95);
            const auto SecondReceipt = co_await Prism::Testing::CloseFixture(TransportOwner94);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(FirstReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(SecondReceipt);
            co_return;
        }
        const auto ServerEndpoint = Server.NativeSocket().local_endpoint();
        ClientA.SetRemote(ServerEndpoint);
        ClientB.SetRemote(ServerEndpoint);
        Server.SetRemote(ClientA.NativeSocket().local_endpoint());
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientB.WriteSome(SvBytes("intruder")));
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientA.WriteSome(SvBytes("trusted")));
        std::array<std::byte, 16> Buffer{};
        const auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 7u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(7))), "trusted");
        const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner96);
        const auto FirstReceipt = co_await Prism::Testing::CloseFixture(TransportOwner95);
        const auto SecondReceipt = co_await Prism::Testing::CloseFixture(TransportOwner94);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(FirstReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(SecondReceipt);
    }

    auto RunAllowAnyPeer(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto TransportOwner93 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Server = *TransportOwner93;
        auto TransportOwner92 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& ClientA = *TransportOwner92;
        auto TransportOwner91 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& ClientB = *TransportOwner91;
        boost::system::error_code OpenError;
        Server.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        Server.NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenError);
        ClientA.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        ClientA.NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenError);
        ClientB.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        ClientB.NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenError);
        EXPECT_FALSE(OpenError);
        if (OpenError)
        {
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner93);
            const auto FirstReceipt = co_await Prism::Testing::CloseFixture(TransportOwner92);
            const auto SecondReceipt = co_await Prism::Testing::CloseFixture(TransportOwner91);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(FirstReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(SecondReceipt);
            co_return;
        }
        const auto ServerEndpoint = Server.NativeSocket().local_endpoint();
        ClientA.SetRemote(ServerEndpoint);
        ClientB.SetRemote(ServerEndpoint);
        Server.AllowAnyPeer();
        Prism::Fault::Failure ErrorCode;
        EXPECT_EQ(([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientA.WriteSome(SvBytes("a"))), 1u);
        EXPECT_EQ(([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await ClientB.WriteSome(SvBytes("b"))), 1u);
        std::array<std::byte, 8> Buffer{};
        Prism::Transport::Unreliable::EndpointType FirstEndpoint;
        Prism::Transport::Unreliable::EndpointType SecondEndpoint;
        const auto First = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server.ReceiveFrom(std::span<std::byte>(Buffer), FirstEndpoint));
        const std::string FirstValue = std::string(
            Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer).first(First))));
        const auto Second = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server.ReceiveFrom(std::span<std::byte>(Buffer), SecondEndpoint));
        const std::string SecondValue = std::string(
            Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer).first(Second))));
        EXPECT_TRUE((FirstValue == "a" && SecondValue == "b") ||
                    (FirstValue == "b" && SecondValue == "a"))
            << "first=" << FirstValue << " second=" << SecondValue;
        EXPECT_NE(FirstEndpoint, SecondEndpoint);
        EXPECT_FALSE(Server.RemoteEndpoint().has_value());
        const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner93);
        const auto FirstReceipt = co_await Prism::Testing::CloseFixture(TransportOwner92);
        const auto SecondReceipt = co_await Prism::Testing::CloseFixture(TransportOwner91);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(FirstReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(SecondReceipt);
    }

    auto RunUdpDatagramRoundTrip(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto TransportOwner90 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Client = *TransportOwner90;
        auto TransportOwner89 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Server = *TransportOwner89;
        boost::system::error_code OpenError;
        Server.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        if (OpenError || !Server.Bind(0))
        {
            EXPECT_TRUE(false) << "Server Open/Bind Failed";
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner89);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner90);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        Client.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        if (OpenError)
        {
            EXPECT_TRUE(false) << "Client Open Failed";
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner89);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner90);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        const auto Local = Server.NativeSocket().local_endpoint();
        auto LocalAddress = Local.address().to_string();
        if (Local.address().is_unspecified())
        {
            LocalAddress = "127.0.0.1";
        }
        if (!Client.Connect(LocalAddress + ":" + std::to_string(Local.port())))
        {
            EXPECT_TRUE(false) << "Connect Failed";
            const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner89);
            const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner90);
            Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
            co_return;
        }
        Prism::Fault::Failure ErrorCode;
        const auto Written = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Client.WriteSome(SvBytes("udp!")));
        EXPECT_EQ(Written, 4u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        std::array<std::byte, 16> Buffer{};
        auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 4u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(4))), "udp!");
        const auto ReverseWritten = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Server.WriteSome(SvBytes("back")));
        EXPECT_EQ(ReverseWritten, 4u);
        ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Client.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 4u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(4))), "back");
        const auto CancelResult = Server.Cancel();
        EXPECT_TRUE(CancelResult.has_value());
        const auto ServerReceipt = co_await Prism::Testing::CloseFixture(TransportOwner89);
        const auto ClientReceipt = co_await Prism::Testing::CloseFixture(TransportOwner90);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipt);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipt);
    }

    auto RunReadAfterClose(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto TransportOwner88 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Transport = *TransportOwner88;
        boost::system::error_code OpenError;
        Transport.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        if (OpenError || !Transport.Bind(0))
        {
            EXPECT_TRUE(false) << "Open/Bind Failed";
            const auto CloseReceipt = co_await Prism::Testing::CloseFixture(TransportOwner88);
            Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt);
            co_return;
        }
        const auto CloseResult = Transport.Close();
        Prism::Fault::Failure ErrorCode;
        std::array<std::byte, 8> Buffer{};
        const auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 0u);
        EXPECT_TRUE(ErrorCode.Failed());
        const auto DrainResult = co_await Transport.Activity()->Drain();
        EXPECT_TRUE(CloseResult.has_value());
        EXPECT_TRUE(DrainResult.has_value());
    }
} // namespace

TEST(Unreliable, DatagramRoundTrip)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunUnreliableDatagramRoundTrip(Ioc));
    }

TEST(Unreliable, WriteWithoutRemoteFails)
    {
        Net::io_context Ioc;
        auto TransportOwner87 = std::make_shared<Prism::Transport::Unreliable>(Ioc.get_executor());
        auto& Transport = *TransportOwner87;
        boost::system::error_code OpenError;
        Transport.NativeSocket().open(Net::ip::udp::v4(), OpenError);
        Transport.NativeSocket().bind({Net::ip::udp::v4(), 0}, OpenError);
        ASSERT_FALSE(OpenError);
        EXPECT_FALSE(Transport.RemoteEndpoint().has_value());
        Prism::Fault::Failure ErrorCode;
        RunCoro(Ioc, RunWriteWithoutRemote(Transport, ErrorCode));
        ASSERT_TRUE(ErrorCode.Failed());
        EXPECT_EQ(ErrorCode.Code, Prism::Fault::Code::InvalidArgument);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, TransportOwner87));
    }

TEST(Unreliable, SourceFiltering)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunSourceFiltering(Ioc));
    }

TEST(Unreliable, AllowAnyPeerAcceptsMultipleSources)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunAllowAnyPeer(Ioc));
    }

TEST(Unreliable, AccessorsCloseCancel)
    {
        Net::io_context Loop;
        auto TransportOwner86 = std::make_shared<Prism::Transport::Unreliable>(Loop.get_executor());
        auto& DatagramCarrier = *TransportOwner86;
        EXPECT_EQ(DatagramCarrier.TransportType(), Prism::Transmission::Type::Udp);
        EXPECT_EQ(DatagramCarrier.NextLayer(), nullptr);
        EXPECT_FALSE(DatagramCarrier.RemoteEndpoint().has_value());

        const Net::ip::udp::endpoint RemoteEndpoint(Net::ip::address_v4::loopback(), 9999);
        DatagramCarrier.SetRemote(RemoteEndpoint);
        ASSERT_TRUE(DatagramCarrier.RemoteEndpoint().has_value());
        EXPECT_EQ(*DatagramCarrier.RemoteEndpoint(), RemoteEndpoint);

        EXPECT_NO_THROW((void)DatagramCarrier.Executor());
        Prism::Transmission::ControlResult CancelResult;
        EXPECT_NO_THROW(CancelResult = DatagramCarrier.Cancel());
        EXPECT_TRUE(CancelResult.has_value());
        Prism::Transmission::ControlResult CloseResult;
        EXPECT_NO_THROW(CloseResult = DatagramCarrier.Close());
        EXPECT_TRUE(CloseResult.has_value());
        Loop.run();
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, TransportOwner86).has_value());
    }

TEST(UdpTransmission, DatagramRoundTrip)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunUdpDatagramRoundTrip(Ioc));
    }

TEST(UdpTransmission, WriteWithoutOpenFails)
    {
        Net::io_context Loop;
        auto TransportOwner85 = std::make_shared<Prism::Transport::Unreliable>(Loop.get_executor());
        auto& DatagramCarrier = *TransportOwner85; // socket 未打开

        Prism::Fault::Failure OperationFailure;
        Net::co_spawn(
            Loop,
                 [&]() -> Net::awaitable<void>
            {
                     const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await DatagramCarrier.WriteSome(SvBytes("x")));
                EXPECT_EQ(ByteCount, 0u);
            },
            Net::detached);
        Loop.run();
        EXPECT_TRUE(OperationFailure.Failed()); // 未绑定/未打开 → 写错误
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner85));
    }

TEST(UdpTransmission, ReadAfterCloseFails)
    {
        Net::io_context Loop;
        RunCoro(Loop, RunReadAfterClose(Loop));
    }
