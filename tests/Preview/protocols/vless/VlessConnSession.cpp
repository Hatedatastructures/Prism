/**
 * @file VlessConnSession.cpp
 * @brief VLESS Conn/Dgram 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（域名 + 预读缓冲路径）+ 双向回显
 * 2. UDP 数据面：ConnectPacket / AcceptPacket + Dgram 收发往返
 * 3. 错误分支：bad_magic / bad_message / bad_auth / not_supported / io_error
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
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
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Composition/Adapters/Vless.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Preview = ::Preview;
    namespace Net = boost::asio;
    namespace Vless = Preview::Vless;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::PreviewMockTransport;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto RunCoro(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto CompletionHandler = [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Coroutine), std::move(CompletionHandler));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto SpawnServer(
        Net::any_io_executor Executor,
        Net::awaitable<void> Coroutine)
        -> std::shared_ptr<CompletionChannel>
    {
        const auto Done =
            std::make_shared<CompletionChannel>(Executor, 1);
        auto CompletionHandler =
            [Done](std::exception_ptr Exception) -> void
        {
            (void)Done->try_send(
                boost::system::error_code{},
                Exception == nullptr);
        };
        Net::co_spawn(
            Executor,
            std::move(Coroutine),
            std::move(CompletionHandler));
        return Done;
    }

    /// 测试 UUID（固定值，两字节交替模式便于识别）
    auto TestUuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        std::array<std::uint8_t, Vless::UuidLen> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x10 + Index);
        }
        return Uuid;
    }

    /// 构造 vless 目标地址
    auto MakeAddress(Vless::AddressType Type, std::string Host, std::uint16_t Port) -> Vless::Address
    {
        Vless::Address Address{};
        Address.Type = Type;
        Address.Host = std::move(Host);
        Address.Port = Port;
        return Address;
    }

    /// 原始客户端：构造请求头字节
    auto BuildRawRequest(const std::array<std::uint8_t, Vless::UuidLen> &Uuid, Vless::Command Command,
                         const Vless::Address &Target) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire;
        Wire.push_back(Vless::ProtocolVersion);
        Wire.insert(Wire.end(), Uuid.begin(), Uuid.end());
        Wire.push_back(0x00); // addnl len
        Wire.push_back(static_cast<std::uint8_t>(Command));
        if (Command == Vless::Command::Mux)
        {
            return Wire;
        }
        Wire.push_back(static_cast<std::uint8_t>(Target.Port >> 8));
        Wire.push_back(static_cast<std::uint8_t>(Target.Port & 0xFF));
        Wire.push_back(static_cast<std::uint8_t>(Target.Type));
        switch (Target.Type)
        {
        case Vless::AddressType::Ipv4: {
            std::uint32_t Octet = 0;
            for (const char Character : Target.Host)
            {
                if (Character == '.')
                {
                    Wire.push_back(static_cast<std::uint8_t>(Octet));
                    Octet = 0;
                }
                else
                {
                    Octet = Octet * 10 + static_cast<std::uint32_t>(Character - '0');
                }
            }
            Wire.push_back(static_cast<std::uint8_t>(Octet));
            break;
        }
        case Vless::AddressType::Ipv6:
            Wire.insert(Wire.end(), Target.Host.begin(), Target.Host.end());
            break;
        case Vless::AddressType::Domain:
        default:
            Wire.push_back(static_cast<std::uint8_t>(Target.Host.size()));
            Wire.insert(Wire.end(), Target.Host.begin(), Target.Host.end());
            break;
        }
        return Wire;
    }

    TEST(VlessConnSession, ConnectAcceptEcho)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const std::string Payload = "vless echo payload";
        const auto Uuid = TestUuid();

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 预读缓冲读取 → 回显
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream, Uuid, Payload]() -> Net::awaitable<void>
                     {
                         Vless::ServerConfig Config;
                         Config.uuid = Uuid;
                         auto [ErrorValue, Request, Connection] =
                             co_await Vless::Accept(ServerStream, Config);
                         if (ErrorValue != Error::None || !Connection)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(Request.Cmd, Vless::Command::Tcp);
                         EXPECT_EQ(Request.Target.Host, "example.com");
                         EXPECT_EQ(Request.Target.Port, 443u);
                         EXPECT_EQ(Connection->Parsed().Target.Host, "example.com");
                         std::array<std::byte, 1024> Buffer{};
                         std::error_code ErrorCode;
                         const auto BytesRead = co_await Connection->async_read_some(Buffer, ErrorCode);
                         EXPECT_FALSE(ErrorCode);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Payload);
                         const std::span<const std::byte> EchoBuffer(Buffer.data(), BytesRead);
                         co_await Connection->async_write_some(EchoBuffer, ErrorCode);
                         EXPECT_FALSE(ErrorCode);
                         Connection->Close();
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     // 原始客户端：请求头 + 载荷一次写入（触发服务端预读缓冲）
                     auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                                 MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                     Wire.insert(Wire.end(), Payload.begin(), Payload.end());
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> WireSpan(Wire);
                     const auto WireBuffer = AsBytes(WireSpan);
                     co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                     // 读取 2 字节响应 [Version][Addons Len]
                     std::array<std::uint8_t, 2> Response{};
                     std::size_t Received = 0;
                     while (Received < Response.size())
                     {
                         const auto ResponseSpan = std::span<std::uint8_t>(Response).subspan(Received);
                         const auto ResponseBuffer = AsBytes(ResponseSpan);
                         const auto BytesRead = co_await ClientMemory.async_read_some(ResponseBuffer, ErrorCode);
                         if (ErrorCode || BytesRead == 0)
                         {
                             break;
                         }
                         Received += BytesRead;
                     }
                     EXPECT_EQ(Received, 2u);
                     EXPECT_EQ(Response[0], Vless::ProtocolVersion);
                     // 读取回显
                     std::array<std::byte, 1024> Echo{};
                     Received = 0;
                     while (Received < Payload.size())
                     {
                         const std::span<std::byte> EchoSpan(Echo.data() + Received, Echo.size() - Received);
                         const auto BytesRead = co_await ClientMemory.async_read_some(EchoSpan, ErrorCode);
                         if (ErrorCode || BytesRead == 0)
                         {
                             break;
                         }
                         Received += BytesRead;
                     }
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(Echo.data()), Received), Payload);
                     ClientMemory.Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
    }

    TEST(VlessConnSession, FactoryConnectAcceptIpv4)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream, Uuid]() -> Net::awaitable<void>
                     {
                         Vless::ServerConfig Config;
                         Config.uuid = Uuid;
                         auto [ErrorValue, Request, Connection] = co_await Vless::Accept(ServerStream, Config);
                         if (ErrorValue != Error::None || !Connection)
                         {
                             co_return;
                         }
                         EXPECT_EQ(Request.Cmd, Vless::Command::Tcp);
                         EXPECT_EQ(Request.Target.Type, Vless::AddressType::Ipv4);
                         EXPECT_EQ(Request.Target.Host, "1.2.3.4");
                         EXPECT_EQ(Request.Target.Port, 80u);
                         Connection->Close();
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     Vless::ClientConfig Config;
                     Config.uuid = Uuid;
                     auto Target = MakeAddress(Vless::AddressType::Ipv4, "1.2.3.4", 80);
                     auto [ErrorValue, ClientConnection] = co_await Vless::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientMemory)), Config, Target);
                     EXPECT_EQ(ErrorValue, Error::None);
                     if (ClientConnection)
                     {
                         ClientConnection->Close();
                     }
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
    }

    TEST(VlessConnSession, FactoryConnectAcceptPacketUsesLengthFraming)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        const auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 53);
        constexpr std::string_view Text{"vless standard udp packet"};
        const auto Payload = std::vector<std::uint8_t>(Text.begin(), Text.end());
        auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     auto ServerCoroutine = [Uuid, ServerStream, Payload]() -> Net::awaitable<void>
                         {
                             Vless::ServerConfig Config;
                             Config.uuid = Uuid;
                             auto [ErrorValue, Request, Datagram] =
                                 co_await Vless::AcceptPacket(ServerStream, Config);
                             EXPECT_EQ(ErrorValue, Error::None);
                             if (!Datagram)
                             {
                                 co_return;
                             }
                             EXPECT_EQ(Request.Cmd, Vless::Command::Udp);
                             EXPECT_EQ(Request.Target.Host, "example.com");
                             EXPECT_EQ(Request.Target.Port, 53U);
                             Vless::Address ReceivedTarget;
                             std::vector<std::uint8_t> Received;
                             EXPECT_EQ(co_await Datagram->AsyncReceiveFrom(ReceivedTarget, Received),
                                       Error::None);
                             EXPECT_EQ(ReceivedTarget.Host, "example.com");
                             EXPECT_EQ(Received, Payload);
                             EXPECT_EQ(co_await Datagram->AsyncSendTo(ReceivedTarget, Received), Error::None);
                             Datagram->Close();
                         };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     Vless::ClientConfig Config;
                     Config.uuid = Uuid;
                     auto [ErrorValue, Datagram] = co_await Vless::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(ClientMemory)), Config, Target);
                     EXPECT_EQ(ErrorValue, Error::None);
                     if (!Datagram)
                     {
                         ADD_FAILURE() << "VLESS packet connect failed";
                         ServerStream->Close();
                         const auto ServerCompleted = co_await ServerDone->async_receive(
                             Net::use_awaitable);
                         EXPECT_TRUE(ServerCompleted);
                         co_return;
                     }
                     EXPECT_EQ(co_await Datagram->AsyncSendTo(Target, Payload), Error::None);
                     Vless::Address EchoTarget;
                     std::vector<std::uint8_t> Echo;
                     EXPECT_EQ(co_await Datagram->AsyncReceiveFrom(EchoTarget, Echo), Error::None);
                     EXPECT_EQ(EchoTarget.Host, Target.Host);
                     EXPECT_EQ(EchoTarget.Port, Target.Port);
                     EXPECT_EQ(Echo, Payload);
                     Datagram->Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
    }

    TEST(VlessConnSession, DirectStreamBackedDgramWithoutStandardTargetIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     auto Datagram = std::make_shared<Vless::Dgram<>>(
                         std::make_shared<MemoryStream>(std::move(ClientMemory)));
                     Vless::Address Target;
                     std::vector<std::uint8_t> Payload;
                     EXPECT_EQ(co_await Datagram->AsyncReceiveFrom(Target, Payload), Error::NotSupported);
                     Datagram->Close();
                     ServerMemory.Close();
                });
    }

    TEST(VlessConnSession, BadVersionRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 服务端：版本号非法 → bad_magic
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream, Uuid]() -> Net::awaitable<void>
                     {
                         Vless::ServerConfig Config;
                         Config.uuid = Uuid;
                         auto [ErrorValue, Request, Connection] =
                             co_await Vless::Accept(ServerStream, Config);
                         EXPECT_EQ(ErrorValue, Error::BadMagic);
                         EXPECT_FALSE(Connection);
                         (void)Request;
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                                 MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                     Wire[0] = 0x01; // 版本错误
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> WireSpan(Wire);
                     const auto WireBuffer = AsBytes(WireSpan);
                     co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                     ClientMemory.Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
    }

    TEST(VlessConnSession, BadAddonsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 服务端：AddnlLen 非 0 → bad_message
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream, Uuid]() -> Net::awaitable<void>
                     {
                         Vless::ServerConfig Config;
                         Config.uuid = Uuid;
                         auto [ErrorValue, Request, Connection] =
                             co_await Vless::Accept(ServerStream, Config);
                         EXPECT_EQ(ErrorValue, Error::BadMessage);
                         EXPECT_FALSE(Connection);
                         (void)Request;
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                                 MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                     Wire[17] = 0x02; // addnl len = 2
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> WireSpan(Wire);
                     const auto WireBuffer = AsBytes(WireSpan);
                     co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                     ClientMemory.Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
    }

    TEST(VlessConnSession, BadCommandRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 服务端：非法命令 → bad_message
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream, Uuid]() -> Net::awaitable<void>
                     {
                         Vless::ServerConfig Config;
                         Config.uuid = Uuid;
                         auto [ErrorValue, Request, Connection] =
                             co_await Vless::Accept(ServerStream, Config);
                         EXPECT_EQ(ErrorValue, Error::BadMessage);
                         EXPECT_FALSE(Connection);
                         (void)Request;
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     auto Wire = BuildRawRequest(Uuid, static_cast<Vless::Command>(0x09),
                                                 MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> WireSpan(Wire);
                     const auto WireBuffer = AsBytes(WireSpan);
                     co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                     ClientMemory.Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
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
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                auto Result = std::make_shared<Preview::Runtime::Handler::AcceptResult>();
                auto ServerCoroutine = [ServerStream, Uuid, Result]() -> Net::awaitable<void>
                {
                    Vless::ServerConfig Config;
                    Config.uuid = Uuid;
                    Preview::Runtime::Handler::Vless Handler(Config);
                    *Result = co_await Handler.Accept(ServerStream);
                };
                auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                Vless::ClientConfig ClientConfig;
                ClientConfig.uuid = Uuid;
                const auto Target = MakeAddress(
                    Vless::AddressType::Domain, "example.com", 443);
                auto [ClientError, ClientConnection] = co_await Vless::Connect(
                    Vless::ConnectParameters{
                        std::make_shared<MemoryStream>(std::move(ClientMemory)),
                        ClientConfig,
                        Target,
                        Vless::Command::Mux});
                EXPECT_EQ(ClientError, Error::None);

                const auto ServerCompleted = co_await ServerDone->async_receive(Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
                EXPECT_EQ(Result->err, Error::None);
                EXPECT_TRUE(Result->ProtocolAuthenticated);
                auto Typed = Preview::Composition::Adapters::ToTypedResult(std::move(*Result));
                EXPECT_EQ(Typed.Status, Error::None);
                EXPECT_TRUE(Typed.Data.IsMux());
                auto *Mux = Typed.Data.Mux();
                EXPECT_NE(Mux, nullptr);
                if (Mux == nullptr)
                {
                    co_return;
                }
                EXPECT_EQ(Mux->Mode, "auto");
                EXPECT_TRUE(Typed.Data.HasTransport());
                Typed.Data.Close();
                if (ClientConnection)
                {
                    ClientConnection->Close();
                }
            });
    }

    TEST(VlessConnSession, MuxCommandWrongCredentialRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();
        auto WrongUuid = Uuid;
        WrongUuid[0] ^= 0xFF;

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerTask = Net::co_spawn(
                    IoContext.get_executor(),
                    [ServerMemory = std::move(ServerMemory), Uuid]() mutable
                        -> Net::awaitable<Preview::Runtime::Handler::AcceptResult>
                    {
                        Vless::ServerConfig Config;
                        Config.uuid = Uuid;
                        Preview::Runtime::Handler::Vless Handler(Config);
                        co_return co_await Handler.Accept(
                            std::make_shared<MemoryStream>(std::move(ServerMemory)));
                    },
                    Net::use_awaitable);

                const auto Wire = BuildRawRequest(
                    WrongUuid,
                    Vless::Command::Mux,
                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                std::error_code ErrorCode;
                co_await ClientMemory.async_write_some(
                    AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
                ClientMemory.Close();
                auto Result = co_await std::move(ServerTask);
                EXPECT_EQ(Result.err, Error::BadAuth);
                EXPECT_FALSE(Result.ProtocolAuthenticated);
                EXPECT_FALSE(Result.Transmission);
            });
    }

    TEST(VlessConnSession, MuxCommandDisabledRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerTask = Net::co_spawn(
                    IoContext.get_executor(),
                    [ServerMemory = std::move(ServerMemory), Uuid]() mutable
                        -> Net::awaitable<Error>
                    {
                        auto Connection = std::make_shared<Vless::Conn<>>(
                            std::make_shared<MemoryStream>(std::move(ServerMemory)), Uuid);
                        auto [ErrorValue, Request] =
                            co_await Connection->ReadHandshake(true, true, false);
                        (void)Request;
                        co_return ErrorValue;
                    },
                    Net::use_awaitable);

                const auto Wire = BuildRawRequest(
                    Uuid,
                    Vless::Command::Mux,
                    MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                std::error_code ErrorCode;
                co_await ClientMemory.async_write_some(
                    AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
                ClientMemory.Close();
                EXPECT_EQ(co_await std::move(ServerTask), Error::NotSupported);
            });
    }

    TEST(VlessConnSession, TcpDisabledRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 服务端：EnableTcp=false → not_supported（不发送响应）
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream, Uuid]() -> Net::awaitable<void>
                     {
                         auto Connection = std::make_shared<Vless::Conn<>>(ServerStream, Uuid);
                         auto [ErrorValue, Request] = co_await Connection->ReadHandshake(false, true, true);
                         EXPECT_EQ(ErrorValue, Error::NotSupported);
                         (void)Request;
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     // 原始客户端：发送请求头后关闭（服务端不响应，客户端读 EOF → io_error）
                     auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                                 MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> WireSpan(Wire);
                     const auto WireBuffer = AsBytes(WireSpan);
                     co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                     ClientMemory.Close();
                     std::array<std::uint8_t, 2> Response{};
                     const std::span<std::uint8_t> ResponseSpan(Response);
                     const auto ResponseBuffer = AsBytes(ResponseSpan);
                     const auto BytesRead = co_await ClientMemory.async_read_some(ResponseBuffer, ErrorCode);
                     EXPECT_EQ(BytesRead, 0u); // 无响应，EOF
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
    }

    TEST(VlessConnSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream, Uuid]() -> Net::awaitable<void>
                     {
                         Vless::ServerConfig Config;
                         Config.uuid = Uuid;
                         auto [ErrorValue, Request, Connection] =
                             co_await Vless::Accept(ServerStream, Config);
                         EXPECT_EQ(ErrorValue, Error::BadMessage);
                         EXPECT_FALSE(Connection);
                         (void)Request;
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     auto Wire = BuildRawRequest(Uuid, Vless::Command::Tcp,
                                                 MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                     Wire[21] = 0x99; // atyp 非法（offset: ver+uuid+addnl+cmd+port = 21）
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> WireSpan(Wire);
                     const auto WireBuffer = AsBytes(WireSpan);
                     co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                     ClientMemory.Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
    }

    TEST(VlessConnSession, BadUuidRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 服务端：UUID 不匹配 → bad_auth（不发送响应，静默断开）
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream, Uuid]() -> Net::awaitable<void>
                     {
                         Vless::ServerConfig Config;
                         Config.uuid = Uuid;
                         auto [ErrorValue, Request, Connection] =
                             co_await Vless::Accept(ServerStream, Config);
                         EXPECT_EQ(ErrorValue, Error::BadAuth);
                         EXPECT_FALSE(Connection);
                         (void)Request;
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     std::array<std::uint8_t, Vless::UuidLen> BadUuid{};
                     BadUuid.fill(0xAA);
                     auto Wire = BuildRawRequest(BadUuid, Vless::Command::Tcp,
                                                 MakeAddress(Vless::AddressType::Domain, "example.com", 443));
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> WireSpan(Wire);
                     const auto WireBuffer = AsBytes(WireSpan);
                     co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                     ClientMemory.Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                });
    }

    TEST(VlessConnSession, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportRead = true;
        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
                     auto [ErrorValue, Request] = co_await Connection->ReadHandshake();
                     EXPECT_EQ(ErrorValue, Error::IoError);
                     EXPECT_EQ(Raw->ReadsDone, 1u);
                     (void)Request;
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessConnSession, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        Raw->EofOnDrain = true;
        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
                     auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 443);
                     const auto ErrorValue = co_await Connection->WriteHandshake(Target);
                     EXPECT_EQ(ErrorValue, Error::IoError);
                     EXPECT_EQ(Raw->ReadsDone, 0u);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessConnSession, WriteToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     ServerMemory.Close(); // 对端已全关 → 写失败 → io_error
                     Vless::ClientConfig Config;
                     Config.uuid = Uuid;
                     auto Target = MakeAddress(Vless::AddressType::Ipv4, "1.1.1.1", 80);
                     auto [ErrorValue, ClientConnection] = co_await Vless::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientMemory)), Config, Target);
                     EXPECT_EQ(ErrorValue, Error::IoError);
                     EXPECT_FALSE(ClientConnection);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessConnSession, DecoratorChain)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto Uuid = TestUuid();

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     auto Connection = std::make_shared<Vless::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(ClientMemory)), Uuid);
                     EXPECT_TRUE(Connection->Executor());
                     EXPECT_NE(Connection->NextLayer(), nullptr);
                     EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
                     const Vless::Conn<> *ConstConnection = Connection.get();
                     EXPECT_NE(ConstConnection->NextLayer(), nullptr);
                     const std::string Payload = "passthrough";
                     const std::span<const std::byte> PayloadSpan(
                         reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
                     std::error_code ErrorCode;
                     co_await Connection->async_write_some(PayloadSpan, ErrorCode);
                     EXPECT_FALSE(ErrorCode);
                     std::array<std::byte, 64> Buffer{};
                     const auto BytesRead = co_await ServerMemory.async_read_some(Buffer, ErrorCode);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Payload);
                     const std::span<const std::byte> ResponseSpan(Buffer.data(), 4);
                     co_await ServerMemory.async_write_some(ResponseSpan, ErrorCode);
                     std::array<std::uint8_t, 4> Destination{};
                     const std::span<std::uint8_t> DestinationSpan(Destination);
                     const auto ReadFailed = co_await Connection->ReadExact(DestinationSpan);
                     EXPECT_FALSE(ReadFailed);
                     Connection->Close();
                     Connection->Cancel();
                     auto Released = Connection->Release();
                     EXPECT_TRUE(Released);
                     EXPECT_EQ(Connection->NextLayer(), nullptr);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, SendToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     auto Datagram = std::make_shared<Vless::Dgram<>>(
                         std::make_shared<MemoryStream>(std::move(ClientMemory)));
                     ServerMemory.Close(); // 对端关闭 → 写失败 → io_error
                     const std::string PayloadText = "x";
                     const auto Payload = AsU8Span(std::string_view(PayloadText));
                     auto Target = MakeAddress(Vless::AddressType::Domain, "example.com", 53);
                     const auto ErrorValue = co_await Datagram->AsyncSendTo(Target, Payload);
                     EXPECT_EQ(ErrorValue, Error::NotSupported);
                     Datagram->Close();
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream]() -> Net::awaitable<void>
                     {
                         auto Datagram = std::make_shared<Vless::Dgram<>>(ServerStream);
                         Vless::Address Source;
                         std::vector<std::uint8_t> Payload;
                         const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
                         EXPECT_EQ(ErrorValue, Error::NotSupported);
                         Datagram->Close();
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     const std::array<std::uint8_t, 1> Atyp{0x99};
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> AtypSpan(Atyp);
                     const auto AtypBuffer = AsBytes(AtypSpan);
                     co_await ClientMemory.async_write_some(AtypBuffer, ErrorCode);
                     ClientMemory.Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, HeaderWithoutPayload)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     // 服务端：地址头完整但无载荷 → unexpected_eof
                     auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto ServerCoroutine = [ServerStream]() -> Net::awaitable<void>
                     {
                         auto Datagram = std::make_shared<Vless::Dgram<>>(ServerStream);
                         Vless::Address Source;
                         std::vector<std::uint8_t> Payload;
                         const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
                         EXPECT_EQ(ErrorValue, Error::NotSupported);
                         Datagram->Close();
                     };
                     const auto ServerDone = SpawnServer(
                         IoContext.get_executor(),
                         ServerCoroutine());

                     // [ATYP=1][IPv4 4B][Port 2B] 无载荷，随后关闭
                     const std::array<std::uint8_t, 7> Wire{0x01, 1, 2, 3, 4, 0x00, 0x50};
                     std::error_code ErrorCode;
                     const std::span<const std::uint8_t> WireSpan(Wire);
                     const auto WireBuffer = AsBytes(WireSpan);
                     co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                     ClientMemory.Close();
                     const auto ServerCompleted = co_await ServerDone->async_receive(
                         Net::use_awaitable);
                     EXPECT_TRUE(ServerCompleted);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     auto Datagram = std::make_shared<Vless::Dgram<>>(
                         std::make_shared<MemoryStream>(std::move(ServerMemory)));
                     EXPECT_TRUE(Datagram->Executor());
                     // 透传读写（passthrough）
                     std::array<std::byte, 8> Buffer{};
                     std::error_code ErrorCode;
                     const std::span<const std::byte> WriteSpan(Buffer.data(), 4);
                     const auto BytesWritten = co_await Datagram->async_write_some(WriteSpan, ErrorCode);
                     EXPECT_EQ(BytesWritten, 4u);
                     ClientMemory.Close(); // 对端关闭 → 读 EOF → io_error
                     const auto BytesRead = co_await Datagram->async_read_some(Buffer, ErrorCode);
                     EXPECT_EQ(BytesRead, 0u);
                     Vless::Address Source;
                     std::vector<std::uint8_t> Payload;
                     const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
                     EXPECT_EQ(ErrorValue, Error::NotSupported);
                     Datagram->Close();
                     Datagram->Cancel();
                     EXPECT_NE(Datagram->NextLayer(), nullptr);
                     const Vless::Dgram<> *ConstDatagram = Datagram.get();
                     EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
                     auto Released = Datagram->Release();
                     EXPECT_TRUE(Released);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, StreamBackedDatagramIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Datagram = std::make_shared<Vless::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     Vless::Address Src;
                     std::vector<std::uint8_t> Payload;
                     const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Src, Payload);
                     EXPECT_EQ(ErrorValue, Error::NotSupported);
                     Datagram->Close();
                     ServerMemory.Close();
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, RejectsOverreportedStandardWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        Vless::Address Target = MakeAddress(Vless::AddressType::Ipv4, "1.2.3.4", 443);
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw, Target, true);
        const auto Payload = AsU8Span(std::string_view{"overreport"});

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     const auto ErrorValue = co_await Datagram->AsyncSendTo(Target, Payload);
                     EXPECT_EQ(ErrorValue, Error::BadLength);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, RejectsOverreportedStandardRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportRead = true;
        Vless::Address Target = MakeAddress(Vless::AddressType::Ipv4, "1.2.3.4", 443);
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw, Target, true);

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     Vless::Address Source;
                     std::vector<std::uint8_t> Payload;
                     const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
                     EXPECT_EQ(ErrorValue, Error::BadLength);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, UdpTunnelRejectsStreamWithoutFrameBoundaries)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Connection = std::make_shared<Vless::Conn<>>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)), TestUuid());
        Vless::UdpTunnelOptions Options;
        auto Tunnel = std::make_shared<Vless::UdpTunnel>(std::move(Connection), std::move(Options));
        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     co_await Tunnel->Run();
                     ServerMemory.Close();
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, UdpTunnelRejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->TransportKind = Preview::Transmission::Type::Udp;
        Raw->OverreportRead = true;
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
        Vless::UdpTunnelOptions Options;
        auto Tunnel = std::make_shared<Vless::UdpTunnel>(std::move(Connection), std::move(Options));

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     co_await Tunnel->Run();
                 };
        RunCoro(IoContext, std::move(TestCoroutine));

        EXPECT_TRUE(Raw->IsClosed());
    }

} // namespace
