#include "SessionSupport.hpp"

#include <expected>
#include <optional>

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <TestSupport/Prism/Protocol/Ingress.hpp>

namespace
{
    auto ExpectVlessAcceptFailure(
        Prism::SharedTransmission ServerStream,
        const std::array<std::uint8_t, Vless::UuidLen> Uuid,
        const Prism::Fault::Code ExpectedCode) -> Net::awaitable<void>
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
        const Prism::Fault::Code ExpectedCode) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto ServerStream = ServerMemory;
        const auto ServerDone = SpawnServer(
            IoContext.get_executor(),
            ExpectVlessAcceptFailure(ServerStream, Uuid, ExpectedCode));
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory->WriteSome(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        (void)ClientMemory->Close();
        const auto ServerCompleted = co_await ServerDone->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
        (void)ErrorCode;
    }

    auto VlessEchoServer(
        Prism::SharedTransmission ServerStream,
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
        const auto ErrorCode = Prism::Fault::ToNative(Read.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes), Payload);
        const std::span<const std::byte> EchoBuffer(Buffer.data(), Read.Bytes);
        const auto Write = co_await Connection->WriteSome(EchoBuffer);
        EXPECT_FALSE(Prism::Fault::ToNative(Write.Failure));
        (void)Connection->Close();
    }

    auto RunConnectAcceptEcho(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        const std::string Payload = "vless echo payload";
        const auto Uuid = TestUuid();
        auto ServerStream = ServerMemory;
        const auto ServerDone = SpawnServer(
            IoContext.get_executor(), VlessEchoServer(ServerStream, Uuid, Payload));
        auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory->WriteSome(AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        std::array<std::uint8_t, 2> Response{};
        std::size_t Received = 0;
        while (Received < Response.size())
        {
            const auto Read = co_await ClientMemory->ReadSome(
                AsBytes(std::span<std::uint8_t>(Response).subspan(Received)));
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
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
            const auto EchoRead = co_await ClientMemory->ReadSome(EchoSpan);
            if (EchoRead.Failure.Failed() || EchoRead.Bytes == 0) break;
            Received += EchoRead.Bytes;
        }
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Echo.data()), Received), Payload);
        (void)ClientMemory->Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    auto VlessIpv4Accept(
        Prism::SharedTransmission ServerStream,
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
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto ServerStream = ServerMemory;
        const auto ServerDone = SpawnServer(
            IoContext.get_executor(), VlessIpv4Accept(ServerStream, Uuid));
        Vless::ClientConfig Config;
        Config.uuid = Uuid;
        const auto Target = MakeAddress(Vless::AddressType::Ipv4, "1.2.3.4", 80);
        auto Result = co_await Vless::Connect(Vless::ConnectParameters{
            ClientMemory, Config, Target});
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
        Prism::SharedTransmission ServerStream,
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
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        const auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 53);
        constexpr std::string_view Text{"vless standard udp packet"};
        const auto Payload = std::vector<std::uint8_t>(Text.begin(), Text.end());
        auto ServerStream = ServerMemory;
        const auto ServerDone = SpawnServer(
            IoContext.get_executor(), VlessPacketEchoServer(ServerStream, Uuid, Payload));
        Vless::ClientConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Vless::ConnectPacket(
            ClientMemory, Config, Target);
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
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        auto Datagram = std::make_shared<Vless::Dgram<>>(
            ClientMemory);
        (void)ServerMemory->Close();
        std::vector<std::uint8_t> Payload;
        const auto Receive = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(Receive.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Receive.WireBytes, 0U);
        (void)Datagram->Close();
        (void)ServerMemory->Close();
    }

    [[nodiscard]] auto MakeIngressBytePool() -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
    }

    auto AcceptVlessMux(
        std::shared_ptr<Prism::Vless::IngressFactory> Handler,
        Prism::SharedTransmission ServerStream)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        co_return co_await Handler->Accept(Prism::Contract::StreamAcceptInput{
            std::move(ServerStream), {}, MakeIngressBytePool()});
    }

    auto DrainVlessIngress(std::shared_ptr<Prism::Vless::IngressFactory> Handler)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Handler->Close();
        co_return co_await Handler->Drain();
    }

    struct VlessHandshakeInput final
    {
        Prism::SharedTransmission Upstream;
        std::array<std::uint8_t, Vless::UuidLen> Uuid{};
        bool EnableTcp{true};
        bool EnableUdp{true};
        bool EnableMux{true};
    };

    auto ReadVlessHandshake(VlessHandshakeInput Input)
        -> Net::awaitable<std::expected<Vless::RequestHeader, Prism::Fault::Failure>>
    {
        auto Connection = std::make_shared<Vless::Conn<>>(
            std::move(Input.Upstream), Input.Uuid);
        co_return co_await Connection->ReadHandshake(
            Input.EnableTcp, Input.EnableUdp, Input.EnableMux);
    }

    struct VlessMuxAdmissionCompletion final
    {
        std::shared_ptr<std::optional<Prism::Contract::AcceptOutcome>> Outcome;
        std::shared_ptr<CompletionChannel> Done;
    };

    auto CompleteVlessMuxAdmission(
        const VlessMuxAdmissionCompletion &Completion,
        std::exception_ptr Exception,
        Prism::Contract::AcceptOutcome Outcome) -> void
    {
        if (Exception)
        {
            *Completion.Outcome = std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(Exception));
        }
        else
        {
            *Completion.Outcome = std::move(Outcome);
        }
        (void)Completion.Done->try_send(boost::system::error_code{}, true);
    }

    struct VlessMuxRootCompletion final
    {
        std::shared_ptr<
            std::optional<std::expected<void, Prism::Fault::Failure>>> Outcome;
        std::shared_ptr<CompletionChannel> Done;
    };

    auto CompleteVlessMuxRoot(
        const VlessMuxRootCompletion &Completion,
        std::exception_ptr Exception,
        std::expected<void, Prism::Fault::Failure> Outcome) -> void
    {
        if (Exception)
        {
            *Completion.Outcome = std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(Exception));
        }
        else
        {
            *Completion.Outcome = std::move(Outcome);
        }
        (void)Completion.Done->try_send(boost::system::error_code{}, true);
    }

    auto RunMuxAcceptedByHandler(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        Vless::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        auto Handler = Prism::Testing::MakeVlessIngress(std::move(ServerConfig),
            Prism::Testing::ProtocolIngressResources{{},
                Prism::Testing::MakeProtocolIngressUseState(), IoContext.get_executor()},
            Vless::IngressRoute{});
        auto ServerStream = ServerMemory;
        auto ServerOutcome =
            std::make_shared<std::optional<Prism::Contract::AcceptOutcome>>();
        const auto ServerDone =
            std::make_shared<CompletionChannel>(IoContext.get_executor(), 1U);
        Net::co_spawn(
            IoContext.get_executor(), AcceptVlessMux(Handler, ServerStream),
            [Completion = VlessMuxAdmissionCompletion{ServerOutcome, ServerDone}](
                std::exception_ptr Exception,
                Prism::Contract::AcceptOutcome Outcome)
            {
                CompleteVlessMuxAdmission(Completion, Exception, std::move(Outcome));
            });
        Vless::ClientConfig Config;
        Config.uuid = Uuid;
        const auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 443);
        auto ConnectResult = co_await Vless::Connect(Vless::ConnectParameters{
            ClientMemory, Config, Target,
            Vless::Command::Mux});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        Vless::SharedConn ClientConnection;
        if (ConnectResult && *ConnectResult) ClientConnection = std::move(*ConnectResult);
        const auto ServerCompleted = co_await ServerDone->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
        if (!ServerOutcome->has_value())
        {
            if (ClientConnection)
            {
                (void)ClientConnection->Close();
                ClientConnection.reset();
            }
            const auto Drained = co_await DrainVlessIngress(Handler);
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(Handler->IsRetired());
            co_return;
        }
        auto Result = std::move(**ServerOutcome);
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
            if (ClientConnection)
            {
                (void)ClientConnection->Close();
                ClientConnection.reset();
            }
            Plane = {};
            const auto Drained = co_await DrainVlessIngress(Handler);
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(Handler->IsRetired());
            co_return;
        }
        EXPECT_TRUE(Mux->Session);
        EXPECT_TRUE(Plane.HasTransport());

        Prism::Contract::MuxRootRequest RootRequest;
        RootRequest.Lease = std::move(Plane.AccountLease);
        RootRequest.GenerationUseState = Handler->GenerationUseState();
        auto RootResult =
            std::make_shared<std::optional<std::expected<void, Prism::Fault::Failure>>>();
        const auto RootDone =
            std::make_shared<CompletionChannel>(IoContext.get_executor(), 1U);
        Net::co_spawn(
            IoContext.get_executor(), Mux->Session->Run(std::move(RootRequest)),
            [Completion = VlessMuxRootCompletion{RootResult, RootDone}](
                std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Outcome)
            {
                CompleteVlessMuxRoot(Completion, Exception, std::move(Outcome));
            });
        if (ClientConnection)
        {
            (void)ClientConnection->Close();
            ClientConnection.reset();
        }
        const auto RootCompleted = co_await RootDone->async_receive(Net::use_awaitable);
        EXPECT_TRUE(RootCompleted);
        if (RootResult->has_value())
        {
            EXPECT_TRUE(**RootResult);
        }
        else
        {
            ADD_FAILURE() << "Mux root completed without a run result";
        }
        Plane = {};
        const auto Drained = co_await DrainVlessIngress(Handler);
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Handler->IsRetired());
    }

    auto RunMuxWrongCredential(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto WrongUuid = Uuid;
        WrongUuid[0] ^= 0xFF;
        Vless::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        auto Handler = Prism::Testing::MakeVlessIngress(std::move(ServerConfig),
            Prism::Testing::ProtocolIngressResources{{},
                Prism::Testing::MakeProtocolIngressUseState(), IoContext.get_executor()},
            Vless::IngressRoute{});
        auto ServerStream = ServerMemory;
        auto ServerTask = Net::co_spawn(
            IoContext.get_executor(), AcceptVlessMux(Handler, ServerStream), Net::use_awaitable);
        const auto Wire = BuildRawRequest(
            WrongUuid, Vless::Command::Mux,
            MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory->WriteSome(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        (void)ClientMemory->Close();
        auto Result = co_await std::move(ServerTask);
        EXPECT_FALSE(Result);
        if (Result)
        {
            const auto Drained = co_await DrainVlessIngress(Handler);
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(Handler->IsRetired());
            co_return;
        }
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::AuthFailed);
        EXPECT_FALSE(Result.error().Native);
        (void)ErrorCode;
        const auto Drained = co_await DrainVlessIngress(Handler);
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Handler->IsRetired());
    }

    auto RunMuxDisabled(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto ServerStream = ServerMemory;
        auto ServerTask = Net::co_spawn(
            IoContext.get_executor(),
            ReadVlessHandshake({ServerStream, Uuid, true, true, false}), Net::use_awaitable);
        const auto Wire = BuildRawRequest(
            Uuid, Vless::Command::Mux,
            MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory->WriteSome(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        (void)ClientMemory->Close();
        auto Result = co_await std::move(ServerTask);
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::NotSupported);
        (void)ErrorCode;
    }

    auto ExpectTcpDisabled(
        Prism::SharedTransmission ServerStream,
        const std::array<std::uint8_t, Vless::UuidLen> Uuid) -> Net::awaitable<void>
    {
        auto Result = co_await ReadVlessHandshake(
            {std::move(ServerStream), Uuid, false, true, true});
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::NotSupported);
    }

    auto RunTcpDisabled(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto ServerStream = ServerMemory;
        auto ServerDone = SpawnServer(
            IoContext.get_executor(), ExpectTcpDisabled(ServerStream, Uuid));
        auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory->WriteSome(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        (void)ClientMemory->Close();
        std::array<std::uint8_t, 2> Response{};
        const auto Read = co_await ClientMemory->ReadSome(AsBytes(std::span<std::uint8_t>(Response)));
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
        (void)ErrorCode;
    }

    auto RunOverreportedRead(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        Raw->OverreportRead = true;
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
        auto Result = co_await Connection->ReadHandshake();
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Raw->ReadsDone, 1u);
    }

    auto RunOverreportedWrite(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        Raw->EofOnDrain = true;
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
        const auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 443);
        auto Result = co_await Connection->WriteHandshake(Target);
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Raw->ReadsDone, 0u);
    }

    auto RunWriteToClosedPeer(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        (void)ServerMemory->Close();
        Vless::ClientConfig Config;
        Config.uuid = TestUuid();
        const auto Target = MakeAddress(Vless::AddressType::Ipv4, "1.1.1.1", 80);
        auto Result = co_await Vless::Connect(Vless::ConnectParameters{
            ClientMemory, Config, Target});
        EXPECT_FALSE(Result);
        if (!Result) EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionAborted);
    }

    auto RunDecoratorChain(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeSharedMemoryPair(IoContext.get_executor());
        auto Connection = std::make_shared<Vless::Conn<>>(
            ClientMemory, TestUuid());
        EXPECT_TRUE(Connection->Executor());
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
        const Vless::Conn<> *ConstConnection = Connection.get();
        EXPECT_NE(ConstConnection->NextLayer(), nullptr);
        const std::string Payload = "passthrough";
        const auto PayloadSpan = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto PayloadWrite = co_await Connection->WriteExact(PayloadSpan);
        EXPECT_FALSE(PayloadWrite.Failure.Failed());
        std::array<std::byte, 64> Buffer{};
        const auto PayloadRead = co_await ServerMemory->ReadSome(Buffer);
        EXPECT_FALSE(PayloadRead.Failure.Failed());
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), PayloadRead.Bytes), Payload);
        const auto EchoWrite = co_await ServerMemory->WriteExact(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_FALSE(EchoWrite.Failure.Failed());
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
                                               Prism::Fault::Code::BadMessage));
    }

    TEST(VlessConnSession, BadAddonsRejected)
    {
        Net::io_context IoContext;
        const auto Uuid = TestUuid();
        auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        Wire[17] = 0x02; // addnl len = 2
        RunCoro(IoContext, VerifyRejectedWire(IoContext, std::move(Wire),
                                               Prism::Fault::Code::BadMessage));
    }

    TEST(VlessConnSession, BadCommandRejected)
    {
        Net::io_context IoContext;
        const auto Uuid = TestUuid();
        auto Wire = BuildRawRequest(Uuid, static_cast<Vless::Command>(0x09),
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        RunCoro(IoContext, VerifyRejectedWire(IoContext, std::move(Wire),
                                               Prism::Fault::Code::BadMessage));
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
                                               Prism::Fault::Code::BadMessage));
    }

    TEST(VlessConnSession, BadUuidRejected)
    {
        Net::io_context IoContext;
        std::array<std::uint8_t, Vless::UuidLen> BadUuid{};
        BadUuid.fill(0xAA);
        auto Wire = BuildRawRequest(BadUuid, Vless::Command::Tcp,
                                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
        RunCoro(IoContext, VerifyRejectedWire(IoContext, std::move(Wire),
                                               Prism::Fault::Code::AuthFailed));
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
