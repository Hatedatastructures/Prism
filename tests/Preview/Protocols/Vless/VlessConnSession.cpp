#include "VlessConnSessionSupport.hpp"

#include <expected>

#include <Preview/Foundation/Memory/BytePool.hpp>
#include <TestSupport/Preview/ProtocolIngressBindings.hpp>

namespace
{
    auto ExpectVlessAcceptFailure(
        Preview::SharedTransmission ServerStream,
        const std::array<std::uint8_t, Vless::UuidLen> Uuid,
        const Preview::Fault::Code ExpectedCode) -> Net::awaitable<void>
    {
        Vless::ServerConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Vless::Accept(std::move(ServerStream), Config);
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, ExpectedCode);
        EXPECT_FALSE(Result.error().Native);
    }

    auto VerifyRejectedWire(
        Net::io_context &IoContext,
        std::vector<std::uint8_t> Wire,
        const Preview::Fault::Code ExpectedCode) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
        const auto ServerDone = SpawnServer(
            IoContext.get_executor(),
            ExpectVlessAcceptFailure(ServerStream, Uuid, ExpectedCode));
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory.WriteSome(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        ClientMemory.Close();
        const auto ServerCompleted = co_await ServerDone->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
        (void)ErrorCode;
    }

    auto VlessEchoServer(
        Preview::SharedTransmission ServerStream,
        const std::array<std::uint8_t, Vless::UuidLen> Uuid,
        const std::string Payload) -> Net::awaitable<void>
    {
        Vless::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await Vless::Accept(std::move(ServerStream), Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection) co_return;
        auto Request = std::move(AcceptResult->Request);
        auto Connection = std::move(AcceptResult->Connection);
        EXPECT_EQ(Request.Cmd, Vless::Command::Tcp);
        EXPECT_EQ(Request.Target.Host, "example.com");
        EXPECT_EQ(Request.Target.Port, 443u);
        EXPECT_EQ(Connection->Parsed().Target.Host, "example.com");
        std::array<std::byte, 1024> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        const auto ErrorCode = Preview::Fault::ToNative(Read.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes), Payload);
        const std::span<const std::byte> EchoBuffer(Buffer.data(), Read.Bytes);
        const auto Write = co_await Connection->WriteSome(EchoBuffer);
        EXPECT_FALSE(Preview::Fault::ToNative(Write.Failure));
        (void)Connection->Close();
    }

    auto RunConnectAcceptEcho(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const std::string Payload = "vless echo payload";
        const auto Uuid = TestUuid();
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
        const auto ServerDone = SpawnServer(
            IoContext.get_executor(), VlessEchoServer(ServerStream, Uuid, Payload));
        auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory.WriteSome(AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        std::array<std::uint8_t, 2> Response{};
        std::size_t Received = 0;
        while (Received < Response.size())
        {
            const auto Read = co_await ClientMemory.ReadSome(
                AsBytes(std::span<std::uint8_t>(Response).subspan(Received)));
            ErrorCode = Preview::Fault::ToNative(Read.Failure);
            if (ErrorCode || Read.Bytes == 0) break;
            Received += Read.Bytes;
        }
        EXPECT_EQ(Received, 2u);
        EXPECT_EQ(Response[0], Vless::ProtocolVersion);
        std::array<std::byte, 1024> Echo{};
        Received = 0;
        while (Received < Payload.size())
        {
            const auto EchoSpan = std::span<std::byte>(Echo).subspan(Received);
            const auto BytesRead = co_await ClientMemory.async_read_some(EchoSpan, ErrorCode);
            if (ErrorCode || BytesRead == 0) break;
            Received += BytesRead;
        }
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Echo.data()), Received), Payload);
        (void)ClientMemory.Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    auto VlessIpv4Accept(
        Preview::SharedTransmission ServerStream,
        const std::array<std::uint8_t, Vless::UuidLen> Uuid) -> Net::awaitable<void>
    {
        Vless::ServerConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Vless::Accept(std::move(ServerStream), Config);
        EXPECT_TRUE(Result);
        if (!Result) co_return;
        EXPECT_TRUE(Result->Connection);
        if (!Result->Connection) co_return;
        EXPECT_EQ(Result->Request.Cmd, Vless::Command::Tcp);
        EXPECT_EQ(Result->Request.Target.Type, Vless::AddressType::Ipv4);
        EXPECT_EQ(Result->Request.Target.Host, "1.2.3.4");
        EXPECT_EQ(Result->Request.Target.Port, 80u);
        (void)Result->Connection->Close();
    }

    auto RunFactoryConnectAcceptIpv4(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
        const auto ServerDone = SpawnServer(
            IoContext.get_executor(), VlessIpv4Accept(ServerStream, Uuid));
        Vless::ClientConfig Config;
        Config.uuid = Uuid;
        const auto Target = MakeAddress(Vless::AddressType::Ipv4, "1.2.3.4", 80);
        auto Result = co_await Vless::Connect(Vless::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(ClientMemory)), Config, Target});
        EXPECT_TRUE(Result);
        if (Result) EXPECT_TRUE(*Result);
        if (Result && *Result)
        {
            (void)(*Result)->Close();
        }
        else if (Result)
        {
            ADD_FAILURE() << "VLESS connect succeeded without a connection owner";
            (void)ServerStream->Close();
        }
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    auto VlessPacketEchoServer(
        Preview::SharedTransmission ServerStream,
        const std::array<std::uint8_t, Vless::UuidLen> Uuid,
        const std::vector<std::uint8_t> Payload) -> Net::awaitable<void>
    {
        Vless::ServerConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Vless::AcceptPacket(std::move(ServerStream), Config);
        EXPECT_TRUE(Result);
        if (!Result) co_return;
        EXPECT_TRUE(Result->Connection);
        if (!Result->Connection) co_return;
        auto Datagram = std::move(Result->Connection);
        EXPECT_EQ(Result->Request.Cmd, Vless::Command::Udp);
        EXPECT_EQ(Result->Request.Target.Host, "example.com");
        EXPECT_EQ(Result->Request.Target.Port, 53U);
        std::vector<std::uint8_t> Received;
        const auto Receive = co_await Datagram->AsyncReceiveDatagram(Received);
        EXPECT_TRUE(Receive.Failure.Succeeded());
        EXPECT_EQ(Received, Payload);
        const auto Send = co_await Datagram->AsyncSendDatagram(Received);
        EXPECT_TRUE(Send.Failure.Succeeded());
        (void)Datagram->Close();
    }

    auto RunFactoryConnectAcceptPacket(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        const auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 53);
        constexpr std::string_view Text{"vless standard udp packet"};
        const auto Payload = std::vector<std::uint8_t>(Text.begin(), Text.end());
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
        const auto ServerDone = SpawnServer(
            IoContext.get_executor(), VlessPacketEchoServer(ServerStream, Uuid, Payload));
        Vless::ClientConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Vless::ConnectPacket(
            std::make_shared<MemoryStream>(std::move(ClientMemory)), Config, Target);
        EXPECT_TRUE(Result);
        if (!Result)
        {
            ADD_FAILURE() << "VLESS packet connect failed";
            (void)ServerStream->Close();
            EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
            co_return;
        }
        EXPECT_TRUE(*Result);
        if (!*Result)
        {
            ADD_FAILURE() << "VLESS packet connect succeeded without a connection owner";
            (void)ServerStream->Close();
            EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
            co_return;
        }
        auto Datagram = std::move(*Result);
        const auto Send = co_await Datagram->AsyncSendDatagram(Payload);
        EXPECT_TRUE(Send.Failure.Succeeded());
        EXPECT_EQ(Send.PayloadBytes, Payload.size());
        EXPECT_EQ(Send.WireBytes, Payload.size() + 2U);
        std::vector<std::uint8_t> Echo;
        const auto Receive = co_await Datagram->AsyncReceiveDatagram(Echo);
        EXPECT_TRUE(Receive.Failure.Succeeded());
        EXPECT_EQ(Receive.PayloadBytes, Echo.size());
        EXPECT_EQ(Receive.WireBytes, Echo.size() + 2U);
        EXPECT_EQ(Echo, Payload);
        (void)Datagram->Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    auto RunDirectStreamDgramRejection(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Datagram = std::make_shared<Vless::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        (void)ServerMemory.Close();
        std::vector<std::uint8_t> Payload;
        const auto Receive = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(Receive.Failure.Code, Preview::Fault::Code::Eof);
        EXPECT_EQ(Receive.WireBytes, 0U);
        (void)Datagram->Close();
        (void)ServerMemory.Close();
    }

    [[nodiscard]] auto MakeIngressBytePool() -> std::shared_ptr<Preview::Memory::BytePool>
    {
        return std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{64U * 1024U, 64U});
    }

    auto AcceptVlessMux(
        std::shared_ptr<Preview::Vless::IngressFactory> Handler,
        Preview::SharedTransmission ServerStream)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        co_return co_await Handler->Accept(Preview::Contract::StreamAcceptInput{
            std::move(ServerStream), {}, MakeIngressBytePool()});
    }

    auto DrainVlessIngress(std::shared_ptr<Preview::Vless::IngressFactory> Handler)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        Handler->Close();
        co_return co_await Handler->Drain();
    }

    struct VlessHandshakeInput final
    {
        Preview::SharedTransmission Upstream;
        std::array<std::uint8_t, Vless::UuidLen> Uuid{};
        bool EnableTcp{true};
        bool EnableUdp{true};
        bool EnableMux{true};
    };

    auto ReadVlessHandshake(VlessHandshakeInput Input)
        -> Net::awaitable<std::expected<Vless::RequestHeader, Preview::Fault::Failure>>
    {
        auto Connection = std::make_shared<Vless::Conn<>>(
            std::move(Input.Upstream), Input.Uuid);
        co_return co_await Connection->ReadHandshake(
            Input.EnableTcp, Input.EnableUdp, Input.EnableMux);
    }

    auto RunMuxAcceptedByHandler(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        Vless::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        auto Handler = Preview::Testing::MakeVlessIngress(std::move(ServerConfig),
            Preview::Testing::ProtocolIngressResources{{},
                Preview::Testing::MakeProtocolIngressUseState(), IoContext.get_executor()},
            Vless::IngressRoute{});
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto ServerTask = Net::co_spawn(
            IoContext.get_executor(), AcceptVlessMux(Handler, ServerStream), Net::use_awaitable);
        Vless::ClientConfig Config;
        Config.uuid = Uuid;
        const auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 443);
        auto ConnectResult = co_await Vless::Connect(Vless::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(ClientMemory)), Config, Target,
            Vless::Command::Mux});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        Vless::SharedConn ClientConnection;
        if (ConnectResult && *ConnectResult) ClientConnection = std::move(*ConnectResult);
        auto Result = co_await std::move(ServerTask);
        EXPECT_TRUE(Result);
        if (!Result)
        {
            if (ClientConnection) (void)ClientConnection->Close();
            const auto Drained = co_await DrainVlessIngress(Handler);
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(Handler->IsRetired());
            co_return;
        }
        EXPECT_TRUE(Result->ProtocolAuthenticated);
        auto Plane = std::move(*Result);
        EXPECT_TRUE(Plane.IsMux());
        auto *Mux = Plane.Mux();
        EXPECT_NE(Mux, nullptr);
        if (Mux == nullptr)
        {
            if (ClientConnection) (void)ClientConnection->Close();
            const auto Drained = co_await DrainVlessIngress(Handler);
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(Handler->IsRetired());
            co_return;
        }
        EXPECT_TRUE(Mux->Session);
        EXPECT_TRUE(Plane.HasTransport());
        (void)Plane.Transport()->Close();
        if (ClientConnection) (void)ClientConnection->Close();
        const auto Drained = co_await DrainVlessIngress(Handler);
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Handler->IsRetired());
    }

    auto RunMuxWrongCredential(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto WrongUuid = Uuid;
        WrongUuid[0] ^= 0xFF;
        Vless::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        auto Handler = Preview::Testing::MakeVlessIngress(std::move(ServerConfig),
            Preview::Testing::ProtocolIngressResources{{},
                Preview::Testing::MakeProtocolIngressUseState(), IoContext.get_executor()},
            Vless::IngressRoute{});
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto ServerTask = Net::co_spawn(
            IoContext.get_executor(), AcceptVlessMux(Handler, ServerStream), Net::use_awaitable);
        const auto Wire = BuildRawRequest(
            WrongUuid, Vless::Command::Mux,
            MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory.WriteSome(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        (void)ClientMemory.Close();
        auto Result = co_await std::move(ServerTask);
        EXPECT_FALSE(Result);
        if (Result)
        {
            const auto Drained = co_await DrainVlessIngress(Handler);
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(Handler->IsRetired());
            co_return;
        }
        EXPECT_EQ(Result.error().Code, Preview::Fault::Code::AuthFailed);
        EXPECT_FALSE(Result.error().Native);
        (void)ErrorCode;
        const auto Drained = co_await DrainVlessIngress(Handler);
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Handler->IsRetired());
    }

    auto RunMuxDisabled(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto ServerTask = Net::co_spawn(
            IoContext.get_executor(),
            ReadVlessHandshake({ServerStream, Uuid, true, true, false}), Net::use_awaitable);
        const auto Wire = BuildRawRequest(
            Uuid, Vless::Command::Mux,
            MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory.WriteSome(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        (void)ClientMemory.Close();
        auto Result = co_await std::move(ServerTask);
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Preview::Fault::Code::NotSupported);
        (void)ErrorCode;
    }

    auto ExpectTcpDisabled(
        Preview::SharedTransmission ServerStream,
        const std::array<std::uint8_t, Vless::UuidLen> Uuid) -> Net::awaitable<void>
    {
        auto Result = co_await ReadVlessHandshake(
            {std::move(ServerStream), Uuid, false, true, true});
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Preview::Fault::Code::NotSupported);
    }

    auto RunTcpDisabled(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto ServerDone = SpawnServer(
            IoContext.get_executor(), ExpectTcpDisabled(ServerStream, Uuid));
        auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory.WriteSome(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        (void)ClientMemory.Close();
        std::array<std::uint8_t, 2> Response{};
        const auto Read = co_await ClientMemory.ReadSome(AsBytes(std::span<std::uint8_t>(Response)));
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
        (void)ErrorCode;
    }

    auto RunOverreportedRead(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportRead = true;
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
        auto Result = co_await Connection->ReadHandshake();
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Preview::Fault::Code::IoError);
        EXPECT_EQ(Raw->ReadsDone, 1u);
    }

    auto RunOverreportedWrite(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        Raw->EofOnDrain = true;
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
        const auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 443);
        auto Result = co_await Connection->WriteHandshake(Target);
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Preview::Fault::Code::IoError);
        EXPECT_EQ(Raw->ReadsDone, 0u);
    }

    auto RunWriteToClosedPeer(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        (void)ServerMemory.Close();
        Vless::ClientConfig Config;
        Config.uuid = TestUuid();
        const auto Target = MakeAddress(Vless::AddressType::Ipv4, "1.1.1.1", 80);
        auto Result = co_await Vless::Connect(Vless::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(ClientMemory)), Config, Target});
        EXPECT_FALSE(Result);
        if (!Result) EXPECT_EQ(Result.error().Code, Preview::Fault::Code::ConnectionAborted);
    }

    auto RunDecoratorChain(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Connection = std::make_shared<Vless::Conn<>>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)), TestUuid());
        EXPECT_TRUE(Connection->Executor());
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
        const Vless::Conn<> *ConstConnection = Connection.get();
        EXPECT_NE(ConstConnection->NextLayer(), nullptr);
        const std::string Payload = "passthrough";
        const auto PayloadSpan = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        std::error_code ErrorCode;
        co_await Connection->async_write_some(PayloadSpan, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        std::array<std::byte, 64> Buffer{};
        const auto BytesRead = co_await ServerMemory.async_read_some(Buffer, ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Payload);
        co_await ServerMemory.async_write_some(std::span<const std::byte>(Buffer.data(), 4), ErrorCode);
        std::array<std::uint8_t, 4> Destination{};
        auto ReadFailed = co_await Connection->ReadExact(std::span<std::uint8_t>(Destination));
        EXPECT_FALSE(ReadFailed);
        (void)Connection->Close();
        (void)Connection->Cancel();
        auto Released = Connection->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Connection->NextLayer(), nullptr);
    }
} // namespace

    TEST(VlessConnSession, ConnectAcceptEcho)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunConnectAcceptEcho(IoContext));
}
    TEST(VlessConnSession, FactoryConnectAcceptIpv4)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunFactoryConnectAcceptIpv4(IoContext));
    }
    TEST(VlessConnSession, FactoryConnectAcceptPacketUsesLengthFraming)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunFactoryConnectAcceptPacket(IoContext));
    }

    TEST(VlessConnSession, DirectStreamBackedDgramWithoutStandardTargetIsRejected)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunDirectStreamDgramRejection(IoContext));
    }

    TEST(VlessConnSession, BadVersionRejected)
    {
        Net::io_context IoContext;
        const auto Uuid = TestUuid();
        auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        Wire[0] = 0x01; // 版本错误
        RunCoro(IoContext, VerifyRejectedWire(IoContext, std::move(Wire),
                                               Preview::Fault::Code::BadMessage));
    }

    TEST(VlessConnSession, BadAddonsRejected)
    {
        Net::io_context IoContext;
        const auto Uuid = TestUuid();
        auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        Wire[17] = 0x02; // addnl len = 2
        RunCoro(IoContext, VerifyRejectedWire(IoContext, std::move(Wire),
                                               Preview::Fault::Code::BadMessage));
    }

    TEST(VlessConnSession, BadCommandRejected)
    {
        Net::io_context IoContext;
        const auto Uuid = TestUuid();
        auto Wire = BuildRawRequest(Uuid, static_cast<Vless::Command>(0x09),
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        RunCoro(IoContext, VerifyRejectedWire(IoContext, std::move(Wire),
                                               Preview::Fault::Code::BadMessage));
    }

    TEST(VlessConnSession, MuxWireOmitsDestinationAndUsesStandardCommand)
    {
        Vless::RequestHeader Request{};
        Request.Uuid = TestUuid();
        Request.Cmd = Vless::Command::Mux;
        Request.Target = MakeAddress(Vless::AddressType::Domain, "ignored.example", 443);

        const std::vector<std::uint8_t> Expected{
            0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x00, 0x03};
        EXPECT_EQ(Vless::BuildRequest(Request), Expected);

        Vless::RequestHeader Parsed{};
        std::size_t Consumed = 0;
        EXPECT_EQ(Vless::ParseRequest(Expected, Parsed, Consumed), Error::None);
        EXPECT_EQ(Consumed, Expected.size());
        EXPECT_EQ(Parsed.Cmd, Vless::Command::Mux);
        EXPECT_EQ(Parsed.Target.Host, "v1.mux.cool");
        EXPECT_EQ(Parsed.Target.Port, 0U);
    }

    TEST(VlessConnSession, MuxCommandAcceptedByHandler)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunMuxAcceptedByHandler(IoContext));
    }

    TEST(VlessConnSession, MuxCommandWrongCredentialRejected)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunMuxWrongCredential(IoContext));
    }

    TEST(VlessConnSession, MuxCommandDisabledRejected)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunMuxDisabled(IoContext));
    }

    TEST(VlessConnSession, TcpDisabledRejected)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunTcpDisabled(IoContext));
    }

    TEST(VlessConnSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        const auto Uuid = TestUuid();
        auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        Wire[21] = 0x99; // atyp 非法（offset: ver+uuid+addnl+cmd+port = 21）
        RunCoro(IoContext, VerifyRejectedWire(IoContext, std::move(Wire),
                                               Preview::Fault::Code::BadMessage));
    }

    TEST(VlessConnSession, BadUuidRejected)
    {
        Net::io_context IoContext;
        std::array<std::uint8_t, Vless::UuidLen> BadUuid{};
        BadUuid.fill(0xAA);
        auto Wire = BuildRawRequest(BadUuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        RunCoro(IoContext, VerifyRejectedWire(IoContext, std::move(Wire),
                                               Preview::Fault::Code::AuthFailed));
    }

    TEST(VlessConnSession, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunOverreportedRead(IoContext));
    }
    TEST(VlessConnSession, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunOverreportedWrite(IoContext));
    }

    TEST(VlessConnSession, WriteToClosedPeer)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunWriteToClosedPeer(IoContext));
    }

    TEST(VlessConnSession, DecoratorChain)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunDecoratorChain(IoContext));
    }
