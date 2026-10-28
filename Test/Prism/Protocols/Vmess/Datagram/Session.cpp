/**
 * @file Session.cpp
 * @brief VMess Conn 与 Dgram 数据面、错误和关闭所有权测试。
 */
#include "../Connection/SessionSupport.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <vector>

namespace
{
    constexpr std::array<std::size_t, 5> DatagramSizes{1U, 64U, 512U, 1200U, 4096U};

    auto MakeDatagramPayload(const std::size_t Size) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Payload(Size);
        for (std::size_t Index = 0; Index < Size; ++Index)
            Payload[Index] = static_cast<std::uint8_t>((Index * 31U + Size) & 0xFFU);
        return Payload;
    }

    /** @brief 验证多尺寸 VMess UDP 往返并关闭 Dgram 与 Conn 两层 owner。 */
    auto RunUdpRoundtripServer(
        const std::shared_ptr<MemoryStream>& Upstream,
        const std::array<std::uint8_t, 16>& Uuid) -> Net::awaitable<bool>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await AcceptVmessDatagram(Upstream, Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            co_return false;
        }
        auto Request = std::move(AcceptResult->Request);
        auto Datagram = std::move(AcceptResult->Connection);
        EXPECT_EQ(Request.Cmd, static_cast<std::uint8_t>(Vmess::Command::Udp));
        EXPECT_EQ(Datagram->TransportType(), Prism::Transmission::Type::Udp);
        for (const auto Size : DatagramSizes)
        {
            std::vector<std::uint8_t> Payload;
            const auto ReceiveError = co_await Datagram->AsyncReceiveDatagram(Payload);
            EXPECT_EQ(DatagramStatus(ReceiveError), FaultStatus(Error::None));
            const auto Expected = MakeDatagramPayload(Size);
            EXPECT_EQ(Payload, Expected);
            if (DatagramStatus(ReceiveError) != FaultStatus(Error::None)) break;
            const auto SendError = co_await Datagram->AsyncSendDatagram(Payload);
            EXPECT_EQ(DatagramStatus(SendError), FaultStatus(Error::None));
            if (DatagramStatus(SendError) != FaultStatus(Error::None)) break;
        }
        EXPECT_TRUE(Datagram->Stream());
        const auto CloseReceipts = co_await CloseVmessDatagram(Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
        co_return true;
    }

    /** @brief 构造含当前时间戳的 VMess 命令 wire 数据。 */
    auto SerializeCommand(
        Vmess::Message Message,
        std::array<std::uint8_t, 512>& Wire,
        std::size_t& WireSize) -> bool
    {
        Vmess::Serializer Serializer(Message.uuid);
        const auto TimeSeconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        Serializer.Reset(Message, TimeSeconds);
        std::error_code ErrorCode;
        WireSize = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);
        return !ErrorCode && Serializer.IsDone();
    }

    /** @brief 接收后立即关闭 VMess UDP 连接。 */
    auto RunAcceptPacketAndClose(
        const std::shared_ptr<MemoryStream>& Upstream,
        const std::array<std::uint8_t, 16>& Uuid) -> Net::awaitable<bool>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await AcceptVmessDatagram(Upstream, Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            co_return false;
        }
        auto Datagram = std::move(AcceptResult->Connection);
        const auto CloseReceipts = co_await CloseVmessDatagram(Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
        co_return true;
    }

    /** @brief 接收 TCP/Mux handoff 后关闭服务端 Conn owner。 */
    auto RunAcceptAndClose(
        const std::shared_ptr<MemoryStream>& Upstream,
        const std::array<std::uint8_t, 16>& Uuid) -> Net::awaitable<bool>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await AcceptVmessStream(Upstream, Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            co_return false;
        }
        auto Connection = std::move(AcceptResult->Connection);
        const auto CloseReceipt = co_await Prism::Testing::CloseFixture(Connection);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt);
        co_return true;
    }

    /** @brief 执行多尺寸 UDP Dgram 双向帧收发并完整等待两端任务。 */
    auto RunUdpDgramRoundtrip(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        VmessTestTask<bool> ServerTask(Context.get_executor());
        ServerTask.Start(RunUdpRoundtripServer(Pair.SecondOwner, Uuid));

        Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto ConnectResult = co_await Vmess::ConnectPacket(
            Pair.FirstOwner, Config,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 53));
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }
        auto Datagram = std::move(*ConnectResult);
        for (const auto Size : DatagramSizes)
        {
            const auto Payload = MakeDatagramPayload(Size);
            const auto SendError = co_await Datagram->AsyncSendDatagram(Payload);
            EXPECT_EQ(DatagramStatus(SendError), FaultStatus(Error::None));
            if (DatagramStatus(SendError) != FaultStatus(Error::None)) break;
            std::vector<std::uint8_t> Response;
            const auto ReceiveError = co_await Datagram->AsyncReceiveDatagram(Response);
            EXPECT_EQ(DatagramStatus(ReceiveError), FaultStatus(Error::None));
            EXPECT_EQ(Response, Payload);
            if (DatagramStatus(ReceiveError) != FaultStatus(Error::None)) break;
        }
        const auto CloseReceipts = co_await CloseVmessDatagram(Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
        EXPECT_TRUE(co_await ServerTask.Wait());
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 发送错误 UUID 认证头并保留 BadAuth 精确结果。 */
    auto RunBadUuidRejected(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        using ServerResultType = std::expected<Vmess::AcceptedConnection, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(
            Context.get_executor());
        ServerTask.Start(AcceptVmessStream(Pair.SecondOwner, Config));

        std::array<std::uint8_t, 16> BadUuid{};
        BadUuid.fill(0xEE);
        std::random_device Random;
        std::array<std::uint8_t, 16> Iv{};
        std::array<std::uint8_t, 16> Key{};
        for (auto& Byte : Iv)
        {
            Byte = static_cast<std::uint8_t>(Random() & 0xFF);
        }
        for (auto& Byte : Key)
        {
            Byte = static_cast<std::uint8_t>(Random() & 0xFF);
        }
        const auto Version = static_cast<std::uint8_t>(Random() & 0xFF);
        const std::array<std::uint8_t, 4> RandomBytes{1, 2, 3, 4};
        const auto TimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        Vmess::RequestHeader Header;
        Header.Version = Vmess::ProtocolVersion;
        Header.Cmd = static_cast<std::uint8_t>(Vmess::Command::Tcp);
        Header.opt = static_cast<std::uint8_t>(Vmess::Option::ChunkStream) |
                     static_cast<std::uint8_t>(Vmess::Option::ChunkMasking);
        Header.sec = Vmess::Security::Aes128Gcm;
        Header.Target = MakeAddress(Vmess::AddressType::Domain, "example.com", 443);
        const auto Plain = Vmess::BuildRequestHeader(
            Header, Vmess::RequestMeta{Iv, Key, Version, 0});
        const auto CommandKey = Vmess::CmdKeyFromUuid(BadUuid);
        const auto Sealed = Vmess::SealAuthHeader(
            CommandKey, Vmess::AuthHeaderInput{Plain, TimeSeconds, RandomBytes});
        const auto Write = co_await Pair.FirstOwner->WriteSome(AsBytes(
            std::span<const std::uint8_t>(Sealed)));
        EXPECT_EQ(Write.Bytes, Sealed.size());
        EXPECT_TRUE(Write.Failure.Succeeded());

        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_FALSE(AcceptResult);
        if (!AcceptResult)
        {
            EXPECT_EQ(AcceptResult.error().Code, Prism::Fault::Code::AuthFailed);
            EXPECT_FALSE(AcceptResult.error().Native);
        }
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 验证未握手 Conn 的 typed 流 I/O 与数据报错误保持原生原因。 */
    auto RunNotOpenRejected(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        auto Connection = std::make_shared<Vmess::Conn<>>(Vmess::ConnOptions{
            .Executor = Pair.FirstOwner->Executor(), .Uuid = Uuid});
        auto Datagram = std::make_shared<Vmess::Dgram<>>(Connection);
        const auto ExpectedNative = static_cast<std::error_code>(
            Prism::make_error_code(Error::NotOpen));
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(Read.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Read.Failure.Native, ExpectedNative);
        const auto Write = co_await Connection->WriteSome(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_EQ(Write.Bytes, 0u);
        EXPECT_EQ(Write.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Write.Failure.Native, ExpectedNative);
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncSendDatagram(
                      AsU8(std::span<std::byte>(Buffer)).first(4))),
                  FaultStatus(Error::NotOpen));
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncReceiveDatagram(Payload)),
                  FaultStatus(Error::NotOpen));

        const auto DatagramCloses = co_await CloseVmessDatagram(Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(DatagramCloses.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(DatagramCloses.Connection);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 对端最终关闭后验证 VMess Connect 保留 IoError。 */
    auto RunWriteToClosedPeer(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto PeerClose = co_await Prism::Testing::CloseFixture(Pair.SecondOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(PeerClose);
        Vmess::ClientConfig Config;
        Config.uuid = TestUuid();
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            Pair.FirstOwner, Config,
            MakeAddress(Vmess::AddressType::Ipv4, "1.1.1.1", 80)});
        EXPECT_FALSE(ConnectResult);
        if (!ConnectResult)
        {
            EXPECT_EQ(ConnectResult.error().Code, Prism::Fault::Code::ConnectionAborted);
        }
        const auto ClientClose = co_await Prism::Testing::CloseFixture(Pair.FirstOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientClose);
    }

    /** @brief 验证未绑定 Conn 控制、Dgram 装饰器导航、取消、半关闭和 Release。 */
    auto RunDecoratorChain(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        auto Unbound = std::make_shared<Vmess::Conn<>>(Vmess::ConnOptions{
            .Executor = Pair.FirstOwner->Executor(), .Uuid = Uuid});
        EXPECT_TRUE(Unbound->Close().has_value());
        EXPECT_TRUE(Unbound->Cancel().has_value());
        auto EmptyRelease = Unbound->Release();
        EXPECT_FALSE(EmptyRelease);
        EXPECT_EQ(Unbound->NextLayer(), nullptr);
        const auto UnboundClose = co_await Prism::Testing::CloseFixture(Unbound);
        Prism::Testing::ExpectFixtureCloseReceipt(UnboundClose);

        VmessTestTask<bool> ServerTask(Context.get_executor());
        ServerTask.Start(RunAcceptAndClose(Pair.SecondOwner, Uuid));
        Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            Pair.FirstOwner, Config,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 443)});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        Vmess::SharedConn Client;
        if (ConnectResult && *ConnectResult) Client = std::move(*ConnectResult);
        if (!Client)
        {
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }
        EXPECT_NE(Client->NextLayer(), nullptr);
        EXPECT_NE(Client->lowest_layer<MemoryStream>(), nullptr);
        EXPECT_TRUE(Client->Executor());
        const auto Cancel = Client->Cancel();
        EXPECT_TRUE(Cancel.has_value());
        const auto HalfClose = co_await Client->WriteShutdown();
        EXPECT_TRUE(HalfClose.has_value());
        const Vmess::Conn<>* ConstClient = Client.get();
        EXPECT_NE(ConstClient->NextLayer(), nullptr);
        auto Released = Client->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Client->NextLayer(), nullptr);

        const auto ClientClose = co_await Prism::Testing::CloseFixture(Client);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientClose);
        if (Released)
        {
            const auto ReleasedClose = co_await Prism::Testing::CloseFixture(Released);
            Prism::Testing::ExpectFixtureCloseReceipt(ReleasedClose);
        }
        EXPECT_TRUE(co_await ServerTask.Wait());
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 验证禁用 UDP 命令在握手响应前以 NotSupported 拒绝。 */
    auto RunUdpCommandDisabledBeforeResponse(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        Config.EnableUdp = false;
        using ServerResultType = std::expected<Vmess::AcceptedConnection, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(
            Context.get_executor());
        ServerTask.Start(AcceptVmessStream(Pair.SecondOwner, Config));

        Vmess::Message Message;
        Message.uuid = Uuid;
        Message.RequestNonce.fill(0x31);
        Message.RequestKey.fill(0x52);
        Message.Cmd = Vmess::CmdUdp;
        Message.dst = MakeAddress(Vmess::AddressType::Domain, "udp.example", 443);
        std::array<std::uint8_t, 512> Wire{};
        std::size_t WireSize = 0;
        if (!SerializeCommand(Message, Wire, WireSize))
        {
            ADD_FAILURE() << "failed to serialize VMess UDP wire";
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }
        const auto Write = co_await Pair.FirstOwner->WriteSome(AsBytes(
            std::span<const std::uint8_t>(Wire).first(WireSize)));
        EXPECT_TRUE(Write.Failure.Succeeded());
        EXPECT_EQ(Write.Bytes, WireSize);

        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_FALSE(AcceptResult);
        if (!AcceptResult)
        {
            EXPECT_EQ(AcceptResult.error().Code, Prism::Fault::Code::NotSupported);
            EXPECT_FALSE(AcceptResult.error().Native);
        }
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 验证 Mux 命令按 TCP Conn handoff 接受并最终关闭。 */
    auto RunMuxCommandAcceptedByTcpHandoff(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        using ServerResultType = std::expected<Vmess::AcceptedConnection, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(
            Context.get_executor());
        ServerTask.Start(AcceptVmessStream(Pair.SecondOwner, Config));

        Vmess::Message Message;
        Message.uuid = Uuid;
        Message.RequestNonce.fill(0x61);
        Message.RequestKey.fill(0x72);
        Message.Cmd = Vmess::CmdMux;
        Message.dst = MakeAddress(Vmess::AddressType::Domain, "mux.example", 443);
        std::array<std::uint8_t, 512> Wire{};
        std::size_t WireSize = 0;
        if (!SerializeCommand(Message, Wire, WireSize))
        {
            ADD_FAILURE() << "failed to serialize VMess Mux wire";
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }
        const auto Write = co_await Pair.FirstOwner->WriteSome(AsBytes(
            std::span<const std::uint8_t>(Wire).first(WireSize)));
        EXPECT_TRUE(Write.Failure.Succeeded());
        EXPECT_EQ(Write.Bytes, WireSize);

        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (AcceptResult && AcceptResult->Connection)
        {
            EXPECT_EQ(AcceptResult->Request.Cmd, Vmess::CmdMux);
            const auto CloseReceipt = co_await Prism::Testing::CloseFixture(AcceptResult->Connection);
            Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt);
        }
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 验证非 Conn 底层的 Dgram 返回 NotOpen 并保留 typed EOF。 */
    auto RunWrapNonConnRejected(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        auto Datagram = std::make_shared<Vmess::Dgram<>>(Pair.FirstOwner);
        const std::string Payload = "x";
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncSendDatagram(AsU8(Payload))),
                  FaultStatus(Error::NotOpen));
        std::vector<std::uint8_t> DatagramPayload;
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncReceiveDatagram(DatagramPayload)),
                  FaultStatus(Error::NotOpen));
        EXPECT_TRUE(Datagram->Executor());

        std::array<std::byte, 8> Buffer{};
        const auto Write = co_await Datagram->WriteSome(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_EQ(Write.Bytes, 4u);
        EXPECT_TRUE(Write.Failure.Succeeded());
        const auto PeerClose = co_await Prism::Testing::CloseFixture(Pair.SecondOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(PeerClose);
        const auto Read = co_await Datagram->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(Read.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_FALSE(Read.Failure.Native);
        EXPECT_TRUE(Datagram->Close().has_value());
        EXPECT_TRUE(Datagram->Cancel().has_value());
        EXPECT_NE(Datagram->NextLayer(), nullptr);
        const Vmess::Dgram<>* ConstDatagram = Datagram.get();
        EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
        auto Stream = Datagram->Stream();
        const auto DatagramClose = co_await Prism::Testing::CloseFixture(Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(DatagramClose);
        auto Released = Datagram->Release();
        EXPECT_TRUE(Released);
        const auto StreamClose = co_await Prism::Testing::CloseFixture(Stream);
        Prism::Testing::ExpectFixtureCloseReceipt(StreamClose);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }
} // namespace

TEST(VmessConnSession, UdpDgramRoundtrip)
{
    Net::io_context Context;
    RunCoroutine(Context, RunUdpDgramRoundtrip(Context));
}

TEST(VmessConnSession, BadUuidRejected)
{
    Net::io_context Context;
    RunCoroutine(Context, RunBadUuidRejected(Context));
}

TEST(VmessConnSession, NotOpenRejected)
{
    Net::io_context Context;
    RunCoroutine(Context, RunNotOpenRejected(Context));
}

TEST(VmessConnSession, WriteToClosedPeer)
{
    Net::io_context Context;
    RunCoroutine(Context, RunWriteToClosedPeer(Context));
}

TEST(VmessConnSession, DecoratorChain)
{
    Net::io_context Context;
    RunCoroutine(Context, RunDecoratorChain(Context));
}

TEST(VmessConnSession, UdpCommandDisabledBeforeResponse)
{
    Net::io_context Context;
    RunCoroutine(Context, RunUdpCommandDisabledBeforeResponse(Context));
}

TEST(VmessConnSession, MuxCommandAcceptedByTcpHandoff)
{
    Net::io_context Context;
    RunCoroutine(Context, RunMuxCommandAcceptedByTcpHandoff(Context));
}

TEST(VmessDgramSession, WrapNonConnRejected)
{
    Net::io_context Context;
    RunCoroutine(Context, RunWrapNonConnRejected(Context));
}
