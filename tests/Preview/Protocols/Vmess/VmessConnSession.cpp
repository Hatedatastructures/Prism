/**
 * @file VmessConnSession.cpp
 * @brief VMess Conn 会话、认证租约、结束块与关闭所有权测试。
 */
#include "VmessConnSessionSupport.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <span>
#include <string>
#include <tuple>
#include <vector>

namespace
{
    /** @brief 验证服务端 Conn 的 echo 请求并关闭其完整 owner 链。 */
    auto RunEchoServer(
        const std::shared_ptr<MemoryStream>& Upstream,
        const std::array<std::uint8_t, 16>& Uuid,
        const std::string& Payload) -> Net::awaitable<bool>
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
        auto Request = std::move(AcceptResult->Request);
        auto Connection = std::move(AcceptResult->Connection);
        EXPECT_EQ(Request.Cmd, static_cast<std::uint8_t>(Vmess::Command::Tcp));
        EXPECT_EQ(Request.dst.Host, "example.com");
        EXPECT_EQ(Request.dst.Port, 443u);
        EXPECT_EQ(Connection->Parsed().dst.Host, "example.com");

        std::array<std::byte, 1024> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_TRUE(Read.Failure.Succeeded());
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(Buffer.data()), Read.Bytes), Payload);
        const auto Write = co_await Connection->WriteSome(
            std::span<const std::byte>(Buffer.data(), Read.Bytes));
        EXPECT_TRUE(Write.Failure.Succeeded());
        EXPECT_EQ(Write.Bytes, Read.Bytes);

        const auto CloseReceipt = co_await Preview::Testing::CloseFixture(Connection);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipt);
        co_return true;
    }

    /** @brief 验证 VMess Conn 客户端与服务端使用同一 owner 链完成 echo。 */
    auto RunClientServerEchoRoundtrip(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        const std::string Payload = "vmess echo payload";
        VmessTestTask<bool> ServerTask(Context.get_executor());
        ServerTask.Start(RunEchoServer(Pair.SecondOwner, Uuid, Payload));

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
            Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }

        const auto Write = co_await Client->WriteSome(AsBytes(std::span<const char>(Payload)));
        EXPECT_TRUE(Write.Failure.Succeeded());
        EXPECT_EQ(Write.Bytes, Payload.size());
        std::array<std::byte, 1024> Buffer{};
        const auto Read = co_await Client->ReadSome(Buffer);
        EXPECT_TRUE(Read.Failure.Succeeded());
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(Buffer.data()), Read.Bytes), Payload);
        const auto ClientClose = co_await Preview::Testing::CloseFixture(Client);
        Preview::Testing::ExpectFixtureCloseReceipt(ClientClose);
        EXPECT_TRUE(co_await ServerTask.Wait());
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 验证目录认证成功后账户租约可取出、重复释放且计数归零。 */
    auto RunDirectoryUuidAuthTransfersAccountLease(Net::io_context& Context)
        -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        auto Directory = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Uuid(CredentialUuid(Uuid)), Preview::AccountId{7301},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Preview::AccountId{7301});
        if (!Record)
        {
            ADD_FAILURE() << "account record missing";
            const auto EndpointCloses = co_await CloseVmessEndpoints(Pair);
            Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.First);
            Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.Second);
            co_return;
        }
        auto Authenticator = Directory->Authenticator;

        Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        ServerConfig.AuthenticatorOwner = Authenticator;
        using ServerResultType = std::expected<Vmess::AcceptedConnection, Preview::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(
            Context.get_executor());
        ServerTask.Start(AcceptVmessStream(Pair.SecondOwner, ServerConfig));

        Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = Uuid;
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            Pair.FirstOwner, ClientConfig,
            MakeAddress(Vmess::AddressType::Domain, "account.test", 443)});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        Vmess::SharedConn Client;
        if (ConnectResult && *ConnectResult) Client = std::move(*ConnectResult);
        EXPECT_TRUE(Client);

        auto ServerResult = co_await ServerTask.Wait();
        EXPECT_TRUE(ServerResult);
        if (ServerResult) EXPECT_TRUE(ServerResult->Connection);
        Vmess::SharedConn Connection;
        if (ServerResult && ServerResult->Connection)
        {
            auto Request = std::move(ServerResult->Request);
            Connection = std::move(ServerResult->Connection);
            EXPECT_EQ(Connection->AccountId(), Preview::AccountId{7301});
            auto Lease = Connection->TakeAuthLease();
            EXPECT_TRUE(Lease);
            EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
            Lease.Release();
            Lease.Release();
            EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        }

        if (Client)
        {
            const auto ClientClose = co_await Preview::Testing::CloseFixture(Client);
            Preview::Testing::ExpectFixtureCloseReceipt(ClientClose);
        }
        if (Connection)
        {
            const auto ServerClose = co_await Preview::Testing::CloseFixture(Connection);
            Preview::Testing::ExpectFixtureCloseReceipt(ServerClose);
        }
        const auto EndpointCloses = co_await CloseVmessEndpoints(Pair);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.First);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.Second);
    }

    /** @brief 服务端读取数据后发送协议结束块，验证客户端获得 typed EOF。 */
    auto RunServerEndBlock(
        const std::shared_ptr<MemoryStream>& Upstream,
        const std::array<std::uint8_t, 16>& Uuid,
        const std::string& Payload) -> Net::awaitable<bool>
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
        auto Request = std::move(AcceptResult->Request);
        auto Connection = std::move(AcceptResult->Connection);

        std::array<std::byte, 1024> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_TRUE(Read.Failure.Succeeded());
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(Buffer.data()), Read.Bytes), Payload);
        const auto ResponseKey = Vmess::detail::Sha256(Request.RequestKey);
        const auto ResponseIv = Vmess::detail::Sha256(Request.RequestNonce);
        std::array<std::uint8_t, 16> Key{};
        std::array<std::uint8_t, 16> Nonce{};
        std::memcpy(Key.data(), ResponseKey.data(), Key.size());
        std::memcpy(Nonce.data(), ResponseIv.data(), Nonce.size());
        Vmess::ChunkEncryptor Encryptor(
            std::span<const std::uint8_t, 16>(Key),
            std::span<const std::uint8_t, 16>(Nonce), Request.Option);
        std::array<std::uint8_t, 34> EndBlock{};
        const auto EndSize = Encryptor.Finish(EndBlock);
        const auto RawUpstream = Connection->Underlying();
        const auto Write = co_await RawUpstream->WriteSome(
            AsBytes(std::span<const std::uint8_t>(EndBlock).first(EndSize)));
        EXPECT_TRUE(Write.Failure.Succeeded());
        EXPECT_EQ(Write.Bytes, EndSize);

        const auto CloseReceipt = co_await Preview::Testing::CloseFixture(Connection);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipt);
        co_return true;
    }

    /** @brief 客户端发送结束块，验证服务端流读取返回正式 EOF。 */
    auto RunClientEndBlockServer(
        const std::shared_ptr<MemoryStream>& Upstream,
        const std::array<std::uint8_t, 16>& Uuid,
        const std::string& Payload) -> Net::awaitable<bool>
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
        auto Request = std::move(AcceptResult->Request);
        auto Connection = std::move(AcceptResult->Connection);

        std::array<std::byte, 1024> Buffer{};
        const auto DataRead = co_await Connection->ReadSome(Buffer);
        EXPECT_TRUE(DataRead.Failure.Succeeded());
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(Buffer.data()), DataRead.Bytes), Payload);
        const auto EndRead = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(EndRead.Bytes, 0u);
        EXPECT_EQ(EndRead.Failure.Code, Preview::Fault::Code::Eof);
        EXPECT_FALSE(EndRead.Failure.Native);
        const auto CloseReceipt = co_await Preview::Testing::CloseFixture(Connection);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipt);
        (void)Request;
        co_return true;
    }

    /** @brief 服务端在 Conn 读挂起时等待客户端最终关闭并回传 typed EOF。 */
    auto RunServerWaitForEof(
        const std::shared_ptr<MemoryStream>& Upstream,
        const std::array<std::uint8_t, 16>& Uuid) -> Net::awaitable<Preview::IoResult>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await AcceptVmessStream(Upstream, Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            co_return Preview::IoResult{0, {Preview::Fault::Code::GenericError}};
        }
        auto Connection = std::move(AcceptResult->Connection);
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        const auto CloseReceipt = co_await Preview::Testing::CloseFixture(Connection);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipt);
        co_return Read;
    }

    /** @brief 验证客户端写半关闭后仍可读取服务端返回的结束块。 */
    auto RunServerEndBlockClient(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        const std::string Payload = "end block payload";
        VmessTestTask<bool> ServerTask(Context.get_executor());
        ServerTask.Start(RunServerEndBlock(Pair.SecondOwner, Uuid, Payload));

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
            const auto EndpointCloses = co_await CloseVmessEndpoints(Pair);
            Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.First);
            Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }

        const auto Write = co_await Client->WriteSome(AsBytes(std::span<const char>(Payload)));
        EXPECT_TRUE(Write.Failure.Succeeded());
        EXPECT_EQ(Write.Bytes, Payload.size());
        const auto HalfClose = co_await Client->WriteShutdown();
        EXPECT_TRUE(HalfClose.has_value());

        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Client->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(Read.Failure.Code, Preview::Fault::Code::Eof);
        EXPECT_FALSE(Read.Failure.Native);
        std::vector<std::uint8_t> Datagram;
        auto DatagramConnection = std::make_shared<Vmess::Dgram<>>(Client);
        EXPECT_EQ(DatagramStatus(co_await DatagramConnection->AsyncReceiveDatagram(Datagram)),
                  Preview::Fault::Code::Eof);

        const auto DatagramClose = co_await CloseVmessDatagram(DatagramConnection);
        Preview::Testing::ExpectFixtureCloseReceipt(DatagramClose.Datagram);
        Preview::Testing::ExpectFixtureCloseReceipt(DatagramClose.Connection);
        EXPECT_TRUE(co_await ServerTask.Wait());
        const auto EndpointCloses = co_await CloseVmessEndpoints(Pair);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.First);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.Second);
    }

    /** @brief 原始客户端发送 VMess 数据块和结束块后半关闭写方向。 */
    auto RunClientEndBlockServerSession(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        const std::string Payload = "Client end block payload";
        VmessTestTask<bool> ServerTask(Context.get_executor());
        ServerTask.Start(RunClientEndBlockServer(Pair.SecondOwner, Uuid, Payload));

        EXPECT_TRUE(co_await RunRawClient(Pair.FirstOwner, Uuid, Payload));
        const auto HalfClose = co_await Pair.FirstOwner->WriteShutdown();
        EXPECT_TRUE(HalfClose.has_value());
        EXPECT_TRUE(co_await ServerTask.Wait());

        const auto EndpointCloses = co_await CloseVmessEndpoints(Pair);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.First);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.Second);
    }

    /** @brief 客户端最终关闭连接后，服务端挂起读完成并报告 clean EOF。 */
    auto RunClientCloseAtFrameBoundary(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = TestUuid();
        VmessTestTask<Preview::IoResult> ServerTask(Context.get_executor());
        ServerTask.Start(RunServerWaitForEof(Pair.SecondOwner, Uuid));

        Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            Pair.FirstOwner, Config,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 443)});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        Vmess::SharedConn Client;
        if (ConnectResult && *ConnectResult) Client = std::move(*ConnectResult);
        EXPECT_TRUE(Client);
        if (!Client)
        {
            const auto EndpointCloses = co_await CloseVmessEndpoints(Pair);
            Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.First);
            Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }

        const auto CloseReceipt = co_await Preview::Testing::CloseFixture(Client);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipt);
        const auto Read = co_await ServerTask.Wait();
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(Read.Failure.Code, Preview::Fault::Code::Eof);
        EXPECT_FALSE(Read.Failure.Native);
        const auto EndpointCloses = co_await CloseVmessEndpoints(Pair);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.First);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointCloses.Second);
    }
} // namespace

TEST(VmessConnOwners, ComposeExplicitOwnerBoundaries)
{
    Net::io_context Context;
    auto Pair = MakeVmessTransportPair(Context);
    auto Connection = std::make_shared<Vmess::Conn<>>(Vmess::ConnOptions{
        .Executor = Pair.FirstOwner->Executor(), .Uuid = TestUuid()});

    EXPECT_FALSE(Connection->IsValid());
    EXPECT_EQ(Connection->NextLayer(), nullptr);
    EXPECT_TRUE(Connection->Executor() == Pair.FirstOwner->Executor());
    const auto ConnectionClose = Preview::Testing::DriveClose(Context, Connection);
    Preview::Testing::ExpectFixtureCloseReceipt(ConnectionClose);
    const auto EndpointClose = Preview::Testing::DriveClose(Context, Pair.FirstOwner);
    Preview::Testing::ExpectFixtureCloseReceipt(EndpointClose);
    const auto PeerClose = Preview::Testing::DriveClose(Context, Pair.SecondOwner);
    Preview::Testing::ExpectFixtureCloseReceipt(PeerClose);
}

TEST(VmessConnSession, ClientServerEchoRoundtrip)
{
    Net::io_context Context;
    RunCoroutine(Context, RunClientServerEchoRoundtrip(Context));
}

TEST(VmessConnSession, DirectoryUuidAuthTransfersAccountLease)
{
    Net::io_context Context;
    RunCoroutine(Context, RunDirectoryUuidAuthTransfersAccountLease(Context));
}

TEST(VmessConnSession, ServerEofOnEndBlock)
{
    Net::io_context Context;
    RunCoroutine(Context, RunServerEndBlockClient(Context));
}

TEST(VmessConnSession, ClientEofOnEndBlock)
{
    Net::io_context Context;
    RunCoroutine(Context, RunClientEndBlockServerSession(Context));
}

TEST(VmessConnSession, ClientCloseAtFrameBoundaryIsCleanEof)
{
    Net::io_context Context;
    RunCoroutine(Context, RunClientCloseAtFrameBoundary(Context));
}
