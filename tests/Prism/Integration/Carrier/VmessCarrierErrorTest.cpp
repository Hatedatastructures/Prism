/**
 * @file VmessCarrierErrorTest.cpp
 * @brief VMess Conn 错误与结束块测试。
 */
#include "CarrierErrorFixture.hpp"

namespace
{
    /** @brief 构造固定 16 字节 VMess 测试 UUID。 */
    auto TestUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x20 + Index);
        }
        return Uuid;
    }

    /** @brief 构造带类型、主机和端口的 VMess 目标地址。 */
    auto MakeAddress(
        Vmess::AddressType Type,
        std::string Host,
        std::uint16_t Port) -> Vmess::Address
    {
        Vmess::Address Address{};
        Address.Type = Type;
        Address.Host = std::move(Host);
        Address.Port = Port;
        return Address;
    }

    /** @brief 用载体执行域构造 VMess 测试连接。 */
    auto MakeVmessConnection(
        Net::any_io_executor Executor,
        std::array<std::uint8_t, 16> Uuid) -> std::shared_ptr<Vmess::Conn<>>
    {
        return std::make_shared<Vmess::Conn<>>(
            Vmess::ConnOptions{std::move(Executor), std::move(Uuid)});
    }

    /** @brief 验证 VMess 未握手连接的流读写与数据报收发均拒绝。 */
    auto RunVmessNotOpenReadWrite(Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        auto Connection = MakeVmessConnection(std::move(Executor), TestUuid());
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(PrismApi::Fault::ToNative(Read.Failure), make_error_code(Error::NotOpen));
        const auto Write = co_await Connection->WriteSome(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_EQ(Write.Bytes, 0u);
        EXPECT_EQ(PrismApi::Fault::ToNative(Write.Failure), make_error_code(Error::NotOpen));
        auto Datagram = std::make_shared<Vmess::Dgram<>>(Connection);
        std::vector<std::uint8_t> Payload;
        const auto ReadPacket = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(PrismApi::Fault::ToNative(ReadPacket.Failure), make_error_code(Error::NotOpen));
        const auto WritePacket = co_await Datagram->AsyncSendDatagram(
            std::span<const std::uint8_t>{});
        EXPECT_EQ(PrismApi::Fault::ToNative(WritePacket.Failure), make_error_code(Error::NotOpen));
        co_await ExpectCloseTransmission(Datagram);
        co_await ExpectCloseTransmission(Connection);
    }

    /** @brief 验证 VMess 客户端收到无效响应长度块时报告认证失败。 */
    auto RunVmessWriteHandshakeBadResponse(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint) -> Net::awaitable<void>
    {
        auto Server = ServerEndpoint;
        const auto ServerTask = SpawnTask(Server->Executor(), RunVmessGarbageServer(Server));
        auto Client = MakeVmessConnection(ClientEndpoint->Executor(), TestUuid());
        const auto Result = co_await Client->WriteHandshake(
            ClientEndpoint,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 443));
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::AuthFailed);
            EXPECT_FALSE(Result.error().Native);
        }
        co_await WaitForTask(ServerTask);
        co_await ExpectCloseTransmission(Client);
    }

    /** @brief 验证 VMess 认证头写入时对端关闭会报告 I/O 错误。 */
    auto RunVmessWriteHandshakeIoError(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint) -> Net::awaitable<void>
    {
        auto Client = MakeVmessConnection(ClientEndpoint->Executor(), TestUuid());
        co_await ExpectCloseTransmission(ServerEndpoint);
        const auto Result = co_await Client->WriteHandshake(
            ClientEndpoint,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 443));
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionAborted);
            EXPECT_FALSE(Result.error().Native);
        }
        co_await ExpectCloseTransmission(Client);
    }

    /** @brief 验证 VMess 认证头被篡改时服务端拒绝握手。 */
    auto RunVmessReadHandshakeBadAuth(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 60> Garbage{};
        Garbage.fill(0xFF);
        const auto Write = co_await ClientEndpoint->WriteSome(
            AsBytes(std::span<const std::uint8_t>(Garbage)));
        EXPECT_EQ(Write.Bytes, Garbage.size());
        EXPECT_TRUE(Write.Failure.Succeeded());
        auto Server = MakeVmessConnection(ServerEndpoint->Executor(), TestUuid());
        auto Result = co_await Server->ReadHandshake(ServerEndpoint);
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::AuthFailed);
            EXPECT_FALSE(Result.error().Native);
        }
        co_await ExpectCloseTransmission(Server);
    }

    /** @brief 验证 VMess 服务端在认证头前遇到对端关闭时报告 I/O 错误。 */
    auto RunVmessReadHandshakeIoError(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint) -> Net::awaitable<void>
    {
        auto Server = MakeVmessConnection(ServerEndpoint->Executor(), TestUuid());
        co_await ExpectCloseTransmission(ClientEndpoint);
        auto Result = co_await Server->ReadHandshake(ServerEndpoint);
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::Eof);
            EXPECT_FALSE(Result.error().Native);
        }
        co_await ExpectCloseTransmission(Server);
    }

    /** @brief 验证 VMess 服务端拒绝底层伪造的超额读取长度。 */
    auto RunVmessReadHandshakeOverreportedRead(
        std::shared_ptr<Prism::PrismMockTransport> Raw) -> Net::awaitable<void>
    {
        auto Server = MakeVmessConnection(Raw->Executor(), TestUuid());
        auto Result = co_await Server->ReadHandshake(Raw);
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::IoError);
            EXPECT_FALSE(Result.error().Native);
        }
        EXPECT_EQ(Raw->ReadsDone, 1u);
        co_await ExpectCloseTransmission(Server);
    }

    /** @brief 验证 VMess chunk tag 不匹配时连接返回认证失败并等待服务端退出。 */
    auto RunVmessChunkTagMismatch(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        auto Server = ServerEndpoint;
        const auto ServerTask = SpawnTask(
            Server->Executor(), RunVmessBadChunkServer(Server, Uuid));
        Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            ClientEndpoint, Config,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 443)});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            co_await ExpectCloseTransmission(Server);
            co_await WaitForTask(ServerTask);
            co_return;
        }
        auto Client = std::move(*ConnectResult);
        const auto EmptyWrite = co_await Client->WriteSome(std::span<const std::byte>{});
        EXPECT_EQ(EmptyWrite.Bytes, 0u);
        EXPECT_TRUE(EmptyWrite.Failure.Succeeded());
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Client->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(PrismApi::Fault::ToNative(Read.Failure), make_error_code(Error::BadAuth));
        co_await ExpectCloseTransmission(Client);
        co_await WaitForTask(ServerTask);
    }

    /** @brief 验证 VMess 服务端关闭后 chunk 读取返回 UnexpectedEof。 */
    auto RunVmessEofDuringChunkRead(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        auto Server = ServerEndpoint;
        const auto ServerTask = SpawnTask(Server->Executor(), RunVmessCloseServer(Server, Uuid));
        Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            ClientEndpoint, Config,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 443)});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            co_await ExpectCloseTransmission(Server);
            co_await WaitForTask(ServerTask);
            co_return;
        }
        auto Client = std::move(*ConnectResult);
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Client->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(PrismApi::Fault::ToNative(Read.Failure), make_error_code(Error::UnexpectedEof));
        co_await ExpectCloseTransmission(Client);
        co_await WaitForTask(ServerTask);
    }

    /** @brief 验证 VMess 结束块令后续流读取稳定返回零字节与正式 EOF。 */
    auto RunVmessFinishBlockThenEof(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        auto Server = ServerEndpoint;
        const auto ServerTask = SpawnTask(Server->Executor(), RunVmessFinishServer(Server, Uuid));
        Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            ClientEndpoint, Config,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 443)});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            co_await ExpectCloseTransmission(Server);
            co_await WaitForTask(ServerTask);
            co_return;
        }
        auto Client = std::move(*ConnectResult);
        std::array<std::byte, 64> Buffer{};
        const auto FirstRead = co_await Client->ReadSome(Buffer);
        EXPECT_EQ(FirstRead.Bytes, 0u);
        EXPECT_EQ(FirstRead.Failure.Code, PrismApi::Fault::Code::Eof);
        EXPECT_EQ(FirstRead.Failure.Native, std::error_code{});
        const auto SecondRead = co_await Client->ReadSome(Buffer);
        EXPECT_EQ(SecondRead.Bytes, 0u);
        EXPECT_EQ(SecondRead.Failure.Code, PrismApi::Fault::Code::Eof);
        EXPECT_EQ(SecondRead.Failure.Native, std::error_code{});
        co_await ExpectCloseTransmission(Client);
        co_await WaitForTask(ServerTask);
    }

    /** @brief 验证 VMess 数据报读取在结束块后稳定返回 UnexpectedEof。 */
    auto RunVmessDatagramFinishEof(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        auto Server = ServerEndpoint;
        const auto ServerTask = SpawnTask(Server->Executor(), RunVmessFinishServer(Server, Uuid));
        Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            ClientEndpoint, Config,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 443),
            Vmess::Command::Udp});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            co_await ExpectCloseTransmission(Server);
            co_await WaitForTask(ServerTask);
            co_return;
        }
        auto Client = std::move(*ConnectResult);
        auto Datagram = std::make_shared<Vmess::Dgram<>>(Client);
        std::vector<std::uint8_t> Payload;
        const auto FirstRead = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(PrismApi::Fault::ToNative(FirstRead.Failure),
                  make_error_code(Error::UnexpectedEof));
        const auto SecondRead = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(PrismApi::Fault::ToNative(SecondRead.Failure),
                  make_error_code(Error::UnexpectedEof));
        co_await ExpectCloseTransmission(Datagram);
        co_await ExpectCloseTransmission(Client);
        co_await WaitForTask(ServerTask);
    }
}

TEST(StealthVmessConnError, NotOpenReadWrite)
    {
        Net::io_context Context;
        RunCoroutine(Context, RunVmessNotOpenReadWrite(Context.get_executor()));
    }
    TEST(StealthVmessConnError, WriteHandshakeBadResponse)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunVmessWriteHandshakeBadResponse(
            ClientEndpoint, ServerEndpoint));
    }
    TEST(StealthVmessConnError, WriteHandshakeIoError)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunVmessWriteHandshakeIoError(
            ClientEndpoint, ServerEndpoint));
    }
    TEST(StealthVmessConnError, ReadHandshakeBadAuth)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunVmessReadHandshakeBadAuth(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthVmessConnError, ReadHandshakeIoError)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunVmessReadHandshakeIoError(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthVmessConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context Context;
        auto Raw = std::make_shared<Prism::PrismMockTransport>(Context.get_executor());
        Raw->OverreportRead = true;

        RunCoroutine(Context, RunVmessReadHandshakeOverreportedRead(Raw));
    }

    TEST(StealthVmessConnError, ChunkTagMismatch)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        const auto Uuid = TestUuid();

        RunMemoryCase(Context, Pair, RunVmessChunkTagMismatch(
            ClientEndpoint, ServerEndpoint, Uuid));
    }

    TEST(StealthVmessConnError, EofDuringChunkRead)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        const auto Uuid = TestUuid();

        RunMemoryCase(Context, Pair, RunVmessEofDuringChunkRead(
            ClientEndpoint, ServerEndpoint, Uuid));
    }

    TEST(StealthVmessConnError, FinishBlockThenEof)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        const auto Uuid = TestUuid();

        RunMemoryCase(Context, Pair, RunVmessFinishBlockThenEof(
            ClientEndpoint, ServerEndpoint, Uuid));
    }

    TEST(StealthVmessConnError, DatagramFinishEof)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        const auto Uuid = TestUuid();

        RunMemoryCase(Context, Pair, RunVmessDatagramFinishEof(
            ClientEndpoint, ServerEndpoint, Uuid));
    }
