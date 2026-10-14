/**
 * @file Ss2022ConnErrorMatrix.cpp
 * @brief Shadowsocks 2022 Conn 错误、认证 lease 和边界测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Account/Account.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace SS2022 = Preview::Shadowsocks2022;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    struct EagerTask final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    auto CompleteEager(EagerTask State, std::exception_ptr Failure) -> void
    {
        if (!*State.Failure)
        {
            *State.Failure = std::move(Failure);
        }
        (void)State.Done->try_send(boost::system::error_code{});
    }

    auto RunCoroutine(Net::io_context &IoContext, Net::awaitable<void> Operation)
        -> void
    {
        std::exception_ptr Failure;
        auto Completion = [&Failure](std::exception_ptr ErrorValue)
        {
            if (!Failure)
            {
                Failure = std::move(ErrorValue);
            }
        };
        IoContext.restart();
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    auto SpawnEager(
        Net::any_io_executor Executor,
        Net::awaitable<void> Operation) -> EagerTask
    {
        EagerTask State{
            std::make_shared<CompletionChannel>(Executor, 1),
            std::make_shared<std::exception_ptr>()};
        Net::co_spawn(
            Executor,
            std::move(Operation),
            [State](std::exception_ptr ErrorValue)
            { CompleteEager(State, std::move(ErrorValue)); });
        return State;
    }

    auto AwaitEager(EagerTask State) -> Net::awaitable<std::exception_ptr>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        co_return *State.Failure;
    }

    [[nodiscard]] auto MakeAddress(
        const SS2022::AddressType Type,
        std::string Host,
        const std::uint16_t Port) -> SS2022::Address
    {
        return SS2022::Address{Type, std::move(Host), Port};
    }

    struct ServerErrorStreams final
    {
        MemoryStream Server;
        std::shared_ptr<MemoryStream> Client;
    };

    struct ServerErrorCase final
    {
        std::array<std::uint8_t, 16> Psk;
        std::vector<std::uint8_t> Wire;
        Error Expected;
    };

    auto RunExpectedServer(
        const std::shared_ptr<MemoryStream> &Server,
        SS2022::ServerConfig Config,
        const Error Expected) -> Net::awaitable<void>
    {
        auto [ErrorValue, Request, Connection] =
            co_await SS2022::Accept(Server, Config);
        EXPECT_EQ(ErrorValue, Expected);
        (void)Request;
        (void)Connection;
    }

    auto RunServerError(
        ServerErrorStreams Streams,
        ServerErrorCase Case) -> Net::awaitable<void>
    {
        auto Server = std::make_shared<MemoryStream>(std::move(Streams.Server));
        SS2022::ServerConfig Config;
        Config.Psk = Case.Psk;
        auto Task = SpawnEager(
            Server->Executor(),
            RunExpectedServer(Server, Config, Case.Expected));
        std::exception_ptr Failure;
        try
        {
            std::error_code ErrorCode;
            const auto Write = co_await Streams.Client->WriteSome(
                AsBytes(std::span<const std::uint8_t>(Case.Wire)));
            ErrorCode = Preview::Fault::ToNative(Write.Failure);
        }
        catch (...)
        {
            Failure = std::current_exception();
        }
        (void)Streams.Client->Close();
        (void)Server->Close();
        const auto TaskFailure = co_await AwaitEager(std::move(Task));
        if (!Failure)
        {
            Failure = TaskFailure;
        }
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    struct BadPasswordCase final
    {
        std::shared_ptr<MemoryStream> Server;
        SS2022::ServerConfig Config;
        MemoryStream ClientMemory;
    };

    auto RunBadPassword(BadPasswordCase Case) -> Net::awaitable<void>
    {
        auto Task = SpawnEager(
            Case.Server->Executor(),
            RunExpectedServer(Case.Server, Case.Config, Error::BadAuth));
        std::exception_ptr Failure;
        SS2022::ClientConfig ClientConfig;
        ClientConfig.Psk.fill(0x42);
        auto ClientTransport = std::make_shared<MemoryStream>(
            std::move(Case.ClientMemory));
        SS2022::SharedConn Connection;
        Error ErrorValue = Error::IoError;
        try
        {
            auto Result = co_await SS2022::Connect(
                ClientTransport,
                ClientConfig,
                MakeAddress(SS2022::AddressType::Domain, "t.internal", 443));
            ErrorValue = std::get<0>(Result);
            Connection = std::get<1>(std::move(Result));
        }
        catch (...)
        {
            Failure = std::current_exception();
            (void)ClientTransport->Close();
        }
        EXPECT_EQ(ErrorValue, Error::IoError);
        if (Connection)
        {
            (void)Connection->Close();
        }
        (void)Case.Server->Close();
        const auto TaskFailure = co_await AwaitEager(std::move(Task));
        if (!Failure)
        {
            Failure = TaskFailure;
        }
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    struct DirectoryServerCase final
    {
        std::shared_ptr<MemoryStream> Server;
        SS2022::ServerConfig Config;
        std::shared_ptr<const Preview::Account::AccountBinding> Record;
    };

    struct DirectoryClientCase final
    {
        MemoryStream ClientMemory;
        std::array<std::uint8_t, 16> Psk;
    };

    auto RunDirectoryServer(DirectoryServerCase Case) -> Net::awaitable<void>
    {
        auto [ErrorValue, Request, Connection] =
            co_await SS2022::Accept(Case.Server, Case.Config);
        EXPECT_EQ(ErrorValue, Error::None);
        if (Connection)
        {
            auto Lease = Connection->TakeAuthLease();
            EXPECT_EQ(Connection->AccountId(), Preview::AccountId{7401});
            EXPECT_TRUE(Lease);
            EXPECT_EQ(Case.Record->Runtime()->ActiveConnections(), 1U);
            Lease.Release();
            Lease.Release();
            EXPECT_EQ(Case.Record->Runtime()->ActiveConnections(), 0U);
            (void)Connection->Close();
        }
        (void)Request;
    }

    auto RunDirectoryPskAuth(
        DirectoryServerCase ServerCase,
        DirectoryClientCase ClientCase) -> Net::awaitable<void>
    {
        auto Task = SpawnEager(
            ServerCase.Server->Executor(), RunDirectoryServer(ServerCase));
        std::exception_ptr Failure;
        SS2022::ClientConfig Config;
        Config.Psk = ClientCase.Psk;
        auto ClientTransport = std::make_shared<MemoryStream>(
            std::move(ClientCase.ClientMemory));
        SS2022::SharedConn Connection;
        Error ErrorValue = Error::IoError;
        try
        {
            auto Result = co_await SS2022::Connect(
                ClientTransport,
                Config,
                MakeAddress(SS2022::AddressType::Domain, "account.test", 443));
            ErrorValue = std::get<0>(Result);
            Connection = std::get<1>(std::move(Result));
        }
        catch (...)
        {
            Failure = std::current_exception();
            (void)ClientTransport->Close();
        }
        EXPECT_EQ(ErrorValue, Error::None);
        if (Connection)
        {
            (void)Connection->Close();
        }
        (void)ServerCase.Server->Close();
        const auto TaskFailure = co_await AwaitEager(std::move(Task));
        if (!Failure)
        {
            Failure = TaskFailure;
        }
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    struct ChunkBoundaryStreams final
    {
        MemoryStream Client;
        MemoryStream Server;
    };

    auto RunChunkBoundaryServer(
        const std::shared_ptr<MemoryStream> &Server,
        std::array<std::uint8_t, 16> Psk) -> Net::awaitable<void>
    {
        SS2022::ServerConfig Config;
        Config.Psk = Psk;
        auto [ErrorValue, Request, Connection] =
            co_await SS2022::Accept(Server, Config);
        EXPECT_EQ(ErrorValue, Error::None);
        if (Connection)
        {
            std::array<std::byte, 64> Buffer{};
            std::error_code ErrorCode;
            const auto Read = co_await Connection->ReadSome(Buffer);
            ErrorCode = Preview::Fault::ToNative(Read.Failure);
            EXPECT_EQ(Read.Bytes, 0U);
            EXPECT_FALSE(ErrorCode);
            (void)Connection->Close();
        }
        (void)Request;
    }

    auto RunClientCloseAtChunkBoundary(
        ChunkBoundaryStreams Streams,
        std::array<std::uint8_t, 16> Psk) -> Net::awaitable<void>
    {
        auto Server = std::make_shared<MemoryStream>(std::move(Streams.Server));
        auto Task = SpawnEager(
            Server->Executor(), RunChunkBoundaryServer(Server, Psk));
        std::exception_ptr Failure;
        SS2022::ClientConfig Config;
        Config.Psk = Psk;
        auto ClientTransport = std::make_shared<MemoryStream>(
            std::move(Streams.Client));
        SS2022::SharedConn Connection;
        Error ErrorValue = Error::IoError;
        try
        {
            auto Result = co_await SS2022::Connect(
                ClientTransport,
                Config,
                MakeAddress(SS2022::AddressType::Domain, "example.com", 443));
            ErrorValue = std::get<0>(Result);
            Connection = std::get<1>(std::move(Result));
        }
        catch (...)
        {
            Failure = std::current_exception();
            ClientTransport->Close();
        }
        EXPECT_EQ(ErrorValue, Error::None);
        EXPECT_NE(Connection, nullptr);
        if (Connection)
        {
            Connection->Close();
        }
        Server->Close();
        const auto TaskFailure = co_await AwaitEager(std::move(Task));
        if (!Failure)
        {
            Failure = TaskFailure;
        }
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    [[nodiscard]] auto MakePsk(const std::uint8_t Value)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Psk{};
        Psk.fill(Value);
        return Psk;
    }

    auto OpenMockServer(
        const std::shared_ptr<Preview::PreviewMockTransport> &Raw,
        const std::array<std::uint8_t, 16> &Psk) -> Net::awaitable<SS2022::SharedConn>
    {
        const auto Wire = Preview::Testing::RecognitionWire::MakeSs2022(Psk);
        std::vector<std::uint8_t> Input;
        Input.reserve(Wire.size());
        for (const auto Byte : Wire)
            Input.push_back(std::to_integer<std::uint8_t>(Byte));
        Raw->InjectRead(std::move(Input));
        SS2022::ServerConfig Config;
        Config.Psk = Psk;
        auto [ErrorValue, Request, Connection] = co_await SS2022::Accept(Raw, Config);
        EXPECT_EQ(ErrorValue, Error::None);
        (void)Request;
        co_return Connection;
    }

    auto RunNativeReadFailure(
        const std::shared_ptr<Preview::PreviewMockTransport> &Raw) -> Net::awaitable<void>
    {
        auto Connection = co_await OpenMockServer(Raw, MakePsk(0x68));
        if (!Connection)
        {
            ADD_FAILURE() << "有效 SS2022 握手没有建立服务端连接";
            co_return;
        }
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Raw->InjectRead({0xAB});
        Raw->SetReadError(Native);
        Raw->ReadErrorBytes = 1;
        std::array<std::byte, 32> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Preview::Fault::Code::ConnectionReset);
        EXPECT_EQ(Read.Failure.Native, Native);
        const auto Reads = Raw->ReadsDone;
        const auto Retry = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Retry.Failure.Code, Read.Failure.Code);
        EXPECT_EQ(Retry.Failure.Native, Native);
        EXPECT_EQ(Raw->ReadsDone, Reads);
        (void)Connection->Close();
    }

    auto RunNativeWriteFailure(
        const std::shared_ptr<Preview::PreviewMockTransport> &Raw) -> Net::awaitable<void>
    {
        auto Connection = co_await OpenMockServer(Raw, MakePsk(0x69));
        if (!Connection)
        {
            ADD_FAILURE() << "有效 SS2022 握手没有建立服务端连接";
            co_return;
        }
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Raw->SetWriteError(Native);
        Raw->WriteErrorBytes = 1;
        const std::array<std::byte, 8> Payload{};
        const auto Write = co_await Connection->WriteSome(Payload);
        EXPECT_EQ(Write.Bytes, 0U);
        EXPECT_EQ(Write.Failure.Code, Preview::Fault::Code::ConnectionReset);
        EXPECT_EQ(Write.Failure.Native, Native);
        const auto Written = Raw->Written.size();
        const auto Retry = co_await Connection->WriteSome(Payload);
        EXPECT_EQ(Retry.Failure.Code, Write.Failure.Code);
        EXPECT_EQ(Retry.Failure.Native, Write.Failure.Native);
        EXPECT_EQ(Retry.Bytes, 0U);
        EXPECT_EQ(Raw->Written.size(), Written);
        (void)Connection->Close();
    }

    auto RunOverreportedRead(
        const std::shared_ptr<Preview::PreviewMockTransport> &Raw)
        -> Net::awaitable<void>
    {
        const auto Psk = MakePsk(0x63);
        auto Connection = std::make_shared<SS2022::Conn<>>(Psk);
        const auto [ErrorValue, Request] =
            co_await Connection->ReadHandshake(Raw);
        EXPECT_EQ(ErrorValue, Error::IoError);
        EXPECT_EQ(Raw->ReadsDone, 1U);
        (void)Request;
        Raw->Close();
    }

    auto RunOverreportedWrite(
        const std::shared_ptr<Preview::PreviewMockTransport> &Raw)
        -> Net::awaitable<void>
    {
        const auto Psk = MakePsk(0x63);
        auto Connection = std::make_shared<SS2022::Conn<>>(Psk);
        const auto ErrorValue = co_await Connection->WriteHandshake(
            Raw,
            MakeAddress(SS2022::AddressType::Domain, "example.com", 443));
        EXPECT_EQ(ErrorValue, Error::IoError);
        EXPECT_EQ(Raw->ReadsDone, 0U);
        Raw->Close();
    }

    TEST(Ss2022ConnErrorMatrix, BadPassword)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        SS2022::ServerConfig Config;
        Config.Psk.fill(0x31);
        RunCoroutine(
            IoContext,
            RunBadPassword(BadPasswordCase{
                Server,
                Config,
                std::move(ClientMemory)}));
    }

    TEST(Ss2022ConnErrorMatrix, DirectoryPskAuthTransfersAccountLease)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Psk = std::array<std::uint8_t, 16>{
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30};
        const std::string PskBytes(
            reinterpret_cast<const char *>(Psk.data()), Psk.size());
        auto Directory = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Psk(PskBytes), Preview::AccountId{7401},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Preview::AccountId{7401});
        ASSERT_TRUE(Record);
        auto Authenticator = Directory->Authenticator;
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        SS2022::ServerConfig Config;
        Config.Psk = Psk;
        Config.Authenticator = Authenticator;
        RunCoroutine(
            IoContext,
            RunDirectoryPskAuth(
                DirectoryServerCase{Server, Config, Record},
                DirectoryClientCase{std::move(ClientMemory), Psk}));
    }

    TEST(Ss2022ConnErrorMatrix, ClientCloseAtChunkBoundaryIsCleanEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(
            IoContext,
            RunClientCloseAtChunkBoundary(
                ChunkBoundaryStreams{
                    std::move(ClientMemory), std::move(ServerMemory)},
                MakePsk(0x51)));
    }

    TEST(Ss2022ConnErrorMatrix, TruncatedHeader)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(
            IoContext,
            RunServerError(
                ServerErrorStreams{
                    std::move(ServerMemory),
                    std::make_shared<MemoryStream>(std::move(ClientMemory))},
                ServerErrorCase{
                    MakePsk(0x62), {0x01, 0x02, 0x03, 0x04}, Error::IoError}));
    }

    TEST(Ss2022ConnErrorMatrix, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(
            IoContext.get_executor());
        Raw->OverreportRead = true;
        RunCoroutine(IoContext, RunOverreportedRead(Raw));
    }

    TEST(Ss2022ConnErrorMatrix, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(
            IoContext.get_executor());
        Raw->OverreportWrite = true;
        Raw->EofOnDrain = true;
        RunCoroutine(IoContext, RunOverreportedWrite(Raw));
    }

    TEST(Ss2022ConnErrorMatrix, ReadPreservesNativeFailure)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        RunCoroutine(IoContext, RunNativeReadFailure(Raw));
    }

    TEST(Ss2022ConnErrorMatrix, WritePreservesNativeFailureAndPoisonsCipherDirection)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        RunCoroutine(IoContext, RunNativeWriteFailure(Raw));
    }
} // namespace
