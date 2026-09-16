/**
 * @file AdapterTest.cpp
 * @brief adapter 接入缝专项测试（阶段 5 v2）
 * @details 覆盖：
 *          - MakeProtocolAccept 的 ctx 装配（Target/identity/IsDgram/PostDial/Inbound 替换）
 *          - 失败映射（bad_auth/not_supported/io_error/unexpected_eof/未知错误）
 *          - 全枚举黄金断言：Fault::ToCode 的 make_error_code.Protocol 分支映射稳定
 *          - 空传输兜底（无错误但无传输 → io_error）
 *          - Session 分支：IsDgram 但未注册 udp_service → not_supported
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Account/Account.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Contract/Handler.hpp>
#include <Preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

#include "../recognition/RecognitionWire.hpp"

namespace
{

    namespace Net = boost::asio;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Runtime = Preview::Runtime;

    using Preview::Testing::RunCoro; // 公共样板（见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    /// 可识别首包（socks5 Greeting）
    auto Socks5Greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto MakePairShared(Net::io_context &Ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [A, B] = MakeMemoryPair(Ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(A)),
                std::make_shared<MemoryStream>(std::move(B))};
    }

    /// 桩协议处理器：按预设结果返回
    class StubHandler final : public Runtime::Handler::ProtocolHandler
    {
    public:
        explicit StubHandler(Runtime::Handler::AcceptResult Result) : result_(std::move(Result)) {}

        auto Accept(SharedTransmission) -> Net::awaitable<Runtime::Handler::AcceptResult> override
        {
            co_return std::move(result_);
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "stub"; }

    private:
        Runtime::Handler::AcceptResult result_;
    };

    auto MakeStubAccept(Runtime::Handler::AcceptResult Result)
        -> Runtime::SessionOptions::ProtocolAcceptFn
    {
        return Runtime::MakeProtocolAccept(std::make_shared<StubHandler>(std::move(Result)));
    }

    /// 构造成功结果
    auto SuccessResult(std::shared_ptr<MemoryStream> Transmission) -> Runtime::Handler::AcceptResult
    {
        Runtime::Handler::AcceptResult r;
        r.err = Error::None;
        r.Target.Host = "example.com";
        r.Target.Port = "443";
        r.identity = "alice";
        r.ProtocolAuthenticated = true;
        r.IsDgram = true;
        r.Transmission = std::move(Transmission);
        return r;
    }

    TEST(AdapterSeam, FillContext)
    {
        Net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto [client_s, inbound_s] = MakePairShared(ioc);
                     const auto *expected = client_s.get();
                     auto Accept = MakeStubAccept(SuccessResult(client_s));

                     Middleware::Context ctx;
                     SharedTransmission yn = inbound_s;
                     const auto ec = co_await Accept(yn, ctx);

                     EXPECT_EQ(ec, Fault::Code::Success);
                     EXPECT_EQ(ctx.Target.Host, "example.com");
                     EXPECT_EQ(ctx.Target.Port, "443");
                     EXPECT_EQ(ctx.identity, "alice");
                     EXPECT_TRUE(ctx.ProtocolAuthenticated);
                     EXPECT_TRUE(ctx.IsDgram);
                     EXPECT_EQ(yn.get(), expected);
                 });
    }

    TEST(AdapterSeam, HttpConnectReplyWaitsForDialAndKeepsTunnelPrefix)
    {
        Net::io_context Io;
        auto [Client, Server] = MakePairShared(Io);
        auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
        Middleware::Context Context;
        SharedTransmission Inbound = Server;
        std::string Response;
        std::string Prefix;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const std::string Wire = "CONNECT example.com:443 HTTP/1.1\r\n"
                                          "Host: example.com:443\r\n"
                                          "\r\n"
                                          "tunnel-prefix";
                std::error_code Error;
                co_await Client->AsyncWrite(Preview::AsBytesSpan(Wire), Error);
                if (Error)
                {
                    ADD_FAILURE() << Error.message();
                    co_return;
                }

                const auto Code = co_await Binding.Accept(Inbound, Context);
                if (Code != Fault::Code::Success || !Context.PostDial)
                {
                    ADD_FAILURE() << "HTTP CONNECT accept did not produce a post-dial callback";
                    co_return;
                }
                co_await Context.PostDial(Fault::Code::Success);

                std::array<std::byte, 128> Buffer{};
                const auto ResponseSize = co_await Client->async_read_some(Buffer, Error);
                if (Error)
                {
                    ADD_FAILURE() << Error.message();
                    co_return;
                }
                Response.assign(reinterpret_cast<const char *>(Buffer.data()), ResponseSize);

                std::array<std::byte, 64> TunnelBuffer{};
                const auto PrefixSize = co_await Inbound->async_read_some(TunnelBuffer, Error);
                if (Error)
                {
                    ADD_FAILURE() << Error.message();
                    co_return;
                }
                Prefix.assign(reinterpret_cast<const char *>(TunnelBuffer.data()), PrefixSize);
            });

        EXPECT_EQ(Response, "HTTP/1.1 200 Connection Established\r\n\r\n");
        EXPECT_EQ(Prefix, "tunnel-prefix");
    }

    TEST(AdapterSeam, HttpAbsoluteFormForwardsOriginFormWithoutProxyResponse)
    {
        Net::io_context Io;
        auto [Client, Server] = MakePairShared(Io);
        auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
        Middleware::Context Context;
        SharedTransmission Inbound = Server;
        std::string Forwarded;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const std::string Wire = "POST http://example.com/upload HTTP/1.1\r\n"
                                          "Host: example.com\r\n"
                                          "Content-Length: 7\r\n"
                                          "\r\n"
                                          "payload";
                std::error_code Error;
                co_await Client->AsyncWrite(Preview::AsBytesSpan(Wire), Error);
                if (Error)
                {
                    ADD_FAILURE() << Error.message();
                    co_return;
                }

                const auto Code = co_await Binding.Accept(Inbound, Context);
                if (Code != Fault::Code::Success || !Context.PostDial)
                {
                    ADD_FAILURE() << "HTTP absolute-form accept did not complete";
                    co_return;
                }
                co_await Context.PostDial(Fault::Code::Success);
                EXPECT_EQ(Context.Target.Host, "example.com");
                EXPECT_EQ(Context.Target.Port, "80");

                std::array<std::byte, 256> Buffer{};
                const auto ForwardedSize = co_await Inbound->async_read_some(Buffer, Error);
                if (Error)
                {
                    ADD_FAILURE() << Error.message();
                    co_return;
                }
                Forwarded.assign(reinterpret_cast<const char *>(Buffer.data()), ForwardedSize);
            });

        EXPECT_EQ(Forwarded,
                  "POST /upload HTTP/1.1\r\n"
                  "Host: example.com\r\n"
                  "Content-Length: 7\r\n"
                  "\r\n"
                  "payload");
    }

    TEST(AdapterSeam, HttpRejectsBadProxyCredentialsWith407)
    {
        Net::io_context Io;
        auto [Client, Server] = MakePairShared(Io);
        Preview::Composition::Recognition::HttpConfig Config;
        Config.RequireAuth = true;
        Config.Authenticator = std::make_shared<Preview::StaticAuthenticator>("user", "pass");
        auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp(
            Preview::Composition::Recognition::CandidateOptions{17, "http-auth", 0, 0, false},
            std::move(Config));
        Middleware::Context Context;
        SharedTransmission Inbound = Server;
        std::string Response;
        Fault::Code Code = Fault::Code::Success;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const std::string Wire = "CONNECT example.com:443 HTTP/1.1\r\n"
                                          "Host: example.com:443\r\n"
                                          "Proxy-Authorization: Basic dXNlcjpiYWQ=\r\n"
                                          "\r\n";
                std::error_code Error;
                co_await Client->AsyncWrite(Preview::AsBytesSpan(Wire), Error);
                if (Error)
                {
                    ADD_FAILURE() << Error.message();
                    co_return;
                }

                Code = co_await Binding.Accept(Inbound, Context);
                std::array<std::byte, 256> Buffer{};
                const auto ResponseSize = co_await Client->AsyncRead(Buffer, Error);
                if (Error)
                {
                    ADD_FAILURE() << Error.message();
                    co_return;
                }
                Response.assign(reinterpret_cast<const char *>(Buffer.data()), ResponseSize);
            });

        EXPECT_EQ(Code, Fault::Code::AuthFailed);
        EXPECT_TRUE(Response.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
    }

    TEST(AdapterSeam, VlessStaticCredentialDoesNotRequireTypedLease)
    {
        Net::io_context Io;
        auto [Client, Server] = MakePairShared(Io);
        const std::array<std::uint8_t, Preview::Vless::UuidLen> Uuid{
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
        const std::string Credential(reinterpret_cast<const char *>(Uuid.data()), Uuid.size());
        auto Authenticator = std::make_shared<Preview::StaticAuthenticator>("", Credential);
        Preview::Vless::ServerConfig Config;
        Config.AuthenticatorOwner = Authenticator;
        Runtime::Handler::Vless Handler(Config);
        Runtime::Handler::AcceptResult Result;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Preview::Vless::RequestHeader Request;
                Request.Uuid = Uuid;
                Request.Cmd = Preview::Vless::Command::Tcp;
                Request.Target = Preview::Vless::Address{
                    Preview::Vless::AddressType::Domain, "example.com", 443};
                const auto Wire = Preview::Vless::BuildRequest(Request);
                std::error_code ErrorCode;
                co_await Client->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Wire.data()), Wire.size()),
                    ErrorCode);
                if (ErrorCode)
                {
                    ADD_FAILURE() << ErrorCode.message();
                    co_return;
                }
                Result = co_await Handler.Accept(Server);
            });

        EXPECT_EQ(Result.err, Error::None);
        EXPECT_TRUE(Result.ProtocolAuthenticated);
        EXPECT_FALSE(Result.AccountLeaseRequired);
        EXPECT_FALSE(Result.AccountLease);
        EXPECT_NE(Result.Transmission, nullptr);
        if (Result.Transmission)
        {
            Result.Transmission->Close();
        }
    }

    TEST(AdapterSeam, TrojanStaticCredentialDoesNotRequireTypedLease)
    {
        Net::io_context Io;
        auto [Client, Server] = MakePairShared(Io);
        const auto Credential = Preview::Trojan::Credential("static-secret");
        auto Authenticator = std::make_shared<Preview::StaticAuthenticator>("", Credential);
        Preview::Trojan::ServerConfig Config;
        Config.password = "different-config-password";
        Config.AuthenticatorOwner = Authenticator;
        Runtime::Handler::Trojan Handler(Config);
        Runtime::Handler::AcceptResult Result;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const auto Wire = Preview::Trojan::BuildRequest(
                    Credential,
                    Preview::Trojan::Command::Connect,
                    Preview::Trojan::Address{
                        Preview::Trojan::AddressType::Domain, "example.com", 443});
                std::error_code ErrorCode;
                co_await Client->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Wire.data()), Wire.size()),
                    ErrorCode);
                if (ErrorCode)
                {
                    ADD_FAILURE() << ErrorCode.message();
                    co_return;
                }
                Result = co_await Handler.Accept(Server);
            });

        EXPECT_EQ(Result.err, Error::None);
        EXPECT_TRUE(Result.ProtocolAuthenticated);
        EXPECT_FALSE(Result.AccountLeaseRequired);
        EXPECT_FALSE(Result.AccountLease);
        EXPECT_NE(Result.Transmission, nullptr);
        if (Result.Transmission)
        {
            Result.Transmission->Close();
        }
    }

    TEST(AdapterSeam, VmessDirectoryCredentialMapsAccountLease)
    {
        Net::io_context Io;
        auto [Client, Server] = MakePairShared(Io);
        const std::array<std::uint8_t, 16> Uuid{
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F};
        std::array<std::byte, 16> CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        const auto Record = std::make_shared<const Preview::Account::AccountRecord>(
            Preview::Account::AccountRecord::CreateRequest{
                .AccountId = Preview::AccountId{7101},
                .CredentialValue = Preview::Account::Credential::Uuid(CredentialBytes),
                .Quota = {.MaxConnections = 1}});
        auto Directory = std::make_shared<Preview::Account::AccountDirectory>();
        ASSERT_TRUE(Directory->Upsert(Record));
        auto ProbeAuthenticator =
            std::make_shared<Preview::Account::ProtocolAuthenticator>(Directory);
        auto ProbeResult = ProbeAuthenticator->Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Preview::Account::CredentialView{
                Preview::Account::CredentialKind::Uuid,
                std::as_bytes(std::span<const std::uint8_t>(Uuid))},
            .Rate = {}});
        ASSERT_TRUE(ProbeResult.Accepted);
        ProbeResult.Lease.Release();
        Preview::Vmess::ServerConfig Config;
        auto Handler = std::make_shared<Runtime::Handler::Vmess>(Config, Directory);
        Runtime::Handler::AcceptResult Result;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Preview::Vmess::Message Message;
                Message.uuid = Uuid;
                Message.RequestNonce.fill(0x31);
                Message.RequestKey.fill(0x42);
                Message.Cmd = Preview::Vmess::CmdTcp;
                Message.dst = Preview::Vmess::Address{
                    Preview::Vmess::AddressType::Domain, "account.example", 443};
                Preview::Vmess::Serializer Serializer(Uuid);
                Serializer.Reset(
                    Message,
                    static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                                   std::chrono::system_clock::now().time_since_epoch())
                                                   .count()));
                std::array<std::uint8_t, 512> Wire{};
                std::error_code ErrorCode;
                const auto WireSize = Serializer.Get(
                    Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);
                if (ErrorCode || !Serializer.IsDone())
                {
                    ADD_FAILURE() << "failed to serialize VMess account wire";
                    co_return;
                }
                Preview::Vmess::Parser Parser(Uuid);
                Parser.Put(Net::const_buffer(Wire.data(), WireSize), ErrorCode);
                if (ErrorCode || !Parser.IsDone())
                {
                    ADD_FAILURE() << "VMess account wire does not parse";
                    co_return;
                }
                co_await Client->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Wire.data()), WireSize),
                    ErrorCode);
                if (ErrorCode)
                {
                    ADD_FAILURE() << ErrorCode.message();
                    co_return;
                }
                Result = co_await Handler->Accept(Server);
            });

        EXPECT_EQ(Result.err, Error::None);
        EXPECT_EQ(Result.AccountId, Preview::AccountId{7101});
        EXPECT_TRUE(Result.AccountLease);
        EXPECT_TRUE(Result.AccountLeaseRequired);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Result.AccountLease.Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        if (Result.Transmission)
        {
            Result.Transmission->Close();
        }
    }

    TEST(AdapterSeam, Ss2022DirectoryCredentialMapsAccountLease)
    {
        Net::io_context Io;
        auto [Client, Server] = MakePairShared(Io);
        const std::array<std::uint8_t, 16> Psk{
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70};
        const std::string PskBytes(reinterpret_cast<const char *>(Psk.data()), Psk.size());
        const auto Record = std::make_shared<const Preview::Account::AccountRecord>(
            Preview::Account::AccountRecord::CreateRequest{
                .AccountId = Preview::AccountId{7102},
                .CredentialValue = Preview::Account::Credential::Psk(PskBytes),
                .Quota = {.MaxConnections = 1}});
        auto Directory = std::make_shared<Preview::Account::AccountDirectory>();
        ASSERT_TRUE(Directory->Upsert(Record));
        auto ProbeAuthenticator =
            std::make_shared<Preview::Account::ProtocolAuthenticator>(Directory);
        auto ProbeResult = ProbeAuthenticator->Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Preview::Account::CredentialView::Psk(PskBytes),
            .Rate = {}});
        ASSERT_TRUE(ProbeResult.Accepted);
        ProbeResult.Lease.Release();
        Preview::Shadowsocks2022::ServerConfig Config;
        auto Handler = std::make_shared<Runtime::Handler::Ss2022>(Config, Directory);
        Runtime::Handler::AcceptResult Result;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const auto Wire = Preview::Testing::RecognitionWire::MakeSs2022(Psk);
                std::error_code ErrorCode;
                Preview::Shadowsocks2022::Parser Parser(Psk);
                Parser.Put(Net::const_buffer(Wire.data(), Wire.size()), ErrorCode);
                if (ErrorCode || !Parser.IsDone())
                {
                    ADD_FAILURE() << "SS2022 account wire does not parse";
                    co_return;
                }
                ErrorCode.clear();
                co_await Client->async_write_some(
                    std::span<const std::byte>(Wire.data(), Wire.size()), ErrorCode);
                if (ErrorCode)
                {
                    ADD_FAILURE() << ErrorCode.message();
                    co_return;
                }
                Result = co_await Handler->Accept(Server);
            });

        EXPECT_EQ(Result.err, Error::None);
        EXPECT_EQ(Result.AccountId, Preview::AccountId{7102});
        EXPECT_TRUE(Result.AccountLease);
        EXPECT_TRUE(Result.AccountLeaseRequired);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Result.AccountLease.Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        if (Result.Transmission)
        {
            Result.Transmission->Close();
        }
    }

    TEST(AdapterSeam, TransfersProtocolAccountLeaseToContext)
    {
        Net::io_context Io;
        const auto Record = std::make_shared<const Preview::Account::AccountRecord>(
            Preview::Account::AccountRecord::CreateRequest{
                .AccountId = Preview::AccountId{7003},
                .CredentialValue = Preview::Account::Credential::Password("credential"),
                .Quota = {.MaxConnections = 1}});
        Preview::Account::AccountDirectory Directory;
        ASSERT_TRUE(Directory.Upsert(Record));
        auto Authenticator = std::make_shared<Preview::DirectoryAuthenticator>(&Directory);
        auto AuthResult = Authenticator->Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Preview::Account::CredentialView::Password("credential"),
            .Rate = {}});
        ASSERT_TRUE(AuthResult.Accepted);
        ASSERT_TRUE(AuthResult.Lease);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);

        Runtime::Handler::AcceptResult Result;
        Result.err = Error::None;
        Result.ProtocolAuthenticated = true;
        Result.AccountId = AuthResult.AccountId;
        Result.AccountLease = std::move(AuthResult.Lease);
        auto [Client, Inbound] = MakePairShared(Io);
        Result.Transmission = Client;
        auto Accept = MakeStubAccept(std::move(Result));

        Middleware::Context Context;
        SharedTransmission Transport = Inbound;
        RunCoro(Io,
                [&]() -> Net::awaitable<void>
                {
                    const auto Code = co_await Accept(Transport, Context);
                    EXPECT_EQ(Code, Fault::Code::Success);
                });

        EXPECT_TRUE(Context.ProtocolAuthenticated);
        EXPECT_EQ(Context.AccountId, Preview::AccountId{7003});
        EXPECT_TRUE(Context.AccountLease);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Context.AccountLease.Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
    }

    TEST(AdapterSeam, EmptyTransmissionFallsBackToIoError)
    {
        Net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto [client_s, inbound_s] = MakePairShared(ioc);
                     Runtime::Handler::AcceptResult r;
                     r.err = Error::None; // 无错误但无传输 → 兜底 io_error
                     auto Accept = MakeStubAccept(std::move(r));

                     Middleware::Context ctx;
                     SharedTransmission yn = inbound_s;
                     const auto ec = co_await Accept(yn, ctx);
                     EXPECT_EQ(ec, Fault::Code::IoError);
                 });
    }

    TEST(AdapterSeam, ErrorMapping)
    {
        const std::pair<Preview::Error, Fault::Code> cases[] = {
            {Preview::Error::BadAuth, Fault::Code::AuthFailed},
            {Preview::Error::AuthFailed, Fault::Code::AuthFailed},
            {Preview::Error::NotSupported, Fault::Code::NotSupported},
            {Preview::Error::IoError, Fault::Code::IoError},
            {Preview::Error::UnexpectedEof, Fault::Code::Eof},
            {static_cast<Preview::Error>(999), Fault::Code::GenericError},
        };
        for (const auto &[err, Want] : cases)
        {
            Net::io_context ioc;
            RunCoro(ioc,
                     [&]() -> Net::awaitable<void>
                     {
                         auto [client_s, inbound_s] = MakePairShared(ioc);
                         Runtime::Handler::AcceptResult r;
                         r.err = err;
                         auto Accept = MakeStubAccept(std::move(r));

                         Middleware::Context ctx;
                         SharedTransmission yn = inbound_s;
                         const auto ec = co_await Accept(yn, ctx);
                         EXPECT_EQ(ec, Want);
                     });
        }
    }

    /// 全枚举黄金断言：Fault::ToCode 的 make_error_code.Protocol 分支映射稳定
    /// （SPEC §3：桥接错误映射只允许一套口径，唯一表在 fault/handling.hpp，
    ///  adapter 层不再保留本地副本）
    TEST(AdapterSeam, ErrorMappingMirrorsFaultToCode)
    {
        const auto Expect = [](Preview::Error e) -> Preview::Fault::Code
        {
            switch (e)
            {
            case Preview::Error::None: return Preview::Fault::Code::Success;
            case Preview::Error::NeedMore: return Preview::Fault::Code::WouldBlock;
            case Preview::Error::UnexpectedEof: return Preview::Fault::Code::Eof;
            case Preview::Error::BadLength:
            case Preview::Error::BadMagic:
            case Preview::Error::BadMessage:
            case Preview::Error::VersionMismatch: return Preview::Fault::Code::BadMessage;
            case Preview::Error::BadAuth:
            case Preview::Error::AuthFailed: return Preview::Fault::Code::AuthFailed;
            case Preview::Error::NotSupported:
            case Preview::Error::Unsupported: return Preview::Fault::Code::NotSupported;
            case Preview::Error::BadAddress: return Preview::Fault::Code::UnsupportedAddress;
            case Preview::Error::NotOpen:
            case Preview::Error::BrokenPipe:
            case Preview::Error::IoError: return Preview::Fault::Code::IoError;
            case Preview::Error::Canceled: return Preview::Fault::Code::Canceled;
            case Preview::Error::Timeout: return Preview::Fault::Code::Timeout;
            case Preview::Error::ProtocolError: return Preview::Fault::Code::ProtocolError;
            case Preview::Error::KdfError: return Preview::Fault::Code::GenericError;
            default: return Preview::Fault::Code::GenericError;
            }
        };

        for (int v = 0; v <= static_cast<int>(Preview::Error::IoError); ++v)
        {
            const auto e = static_cast<Preview::Error>(v);
            EXPECT_EQ(Expect(e), Preview::Fault::ToCode(Preview::make_error_code(e)))
                << "mismatch at Preview::Error value " << v;
        }
        // 越界枚举（无对应 case）：走 default 分支
        const auto bogus = static_cast<Preview::Error>(999);
        EXPECT_EQ(Preview::Fault::Code::GenericError,
                  Preview::Fault::ToCode(Preview::make_error_code(bogus)));
    }

    TEST(AdapterSeam, SessionRejectsDgramWithoutUdpService)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = MakePairShared(ioc);
        auto [data_s, peer_s] = MakePairShared(ioc);

        Runtime::SessionOptions opts;
        Runtime::Handler::AcceptResult r;
        r.err = Error::None;
        r.IsDgram = true;
        r.Transmission = std::move(data_s);
        opts.AcceptProtocol = MakeStubAccept(std::move(r));
        Runtime::Session Session(std::move(opts));

        Fault::Code Arc = Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 先写入可识别首包，recognition 预读不挂起
                     std::error_code wec;
                     const auto payload = Socks5Greeting();
                     co_await inbound_s->async_write_some(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                         wec);

                     Arc = co_await Session.Run(client_s);
                 });
        EXPECT_EQ(Arc, Fault::Code::NotSupported);
    }

} // namespace
