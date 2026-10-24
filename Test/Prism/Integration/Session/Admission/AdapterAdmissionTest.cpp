/**
 * @file AdapterAdmissionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "AdapterTestSupport.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <vector>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Test/Prism/Transport/Core/TransportResources.hpp>

namespace
{
    struct AdmissionRetireRun final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        Fault::Failure Cause;
        Fault::Failure Result;
        bool Prepared{false};
        bool Drained{false};
    };

    auto RunAdmissionRetirement(std::shared_ptr<AdmissionRetireRun> State)
        -> Net::awaitable<void>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(State->Server);
        if (!Prepared)
        {
            State->Result = Prepared.error();
            co_return;
        }
        State->Prepared = true;
        auto Admission = std::move(*Prepared);
        State->Result = co_await Admission.Retire(State->Cause);
        const auto Drain = co_await State->Server->Activity()->Drain();
        State->Drained = static_cast<bool>(Drain);
    }

    auto RunFillContext(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [Client, Inbound] = MakePairShared(IoContext);
        const auto *Expected = Client.get();
        auto Accept = MakeStubAccept(SuccessResult(Client));
        Middleware::Context Context;
        SharedTransmission Transport = Inbound;
        auto Accepted = co_await Accept->Accept(
            Prism::Testing::MakeAdapterAcceptInput(Transport));
        const auto Code = Accepted ? Fault::Code::Success
            : Accepted.error().Code;
        if (Accepted)
        {
            Context.SetDataPlane(std::move(*Accepted));
            Transport = Context.Inbound();
        }
        EXPECT_EQ(Code, Fault::Code::Success);
        EXPECT_EQ(Context.Target().Host, *Prism::Network::ParseHost("example.com"));
        EXPECT_EQ(Context.Target().Port, 443);
        EXPECT_EQ(Context.Identity(), "alice");
        EXPECT_TRUE(Context.ProtocolAuthenticated());
        EXPECT_TRUE(Context.IsDatagram());
        EXPECT_EQ(Transport.get(), Expected);
    }

    struct HttpConnectRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        SharedTransmission Inbound;
        std::shared_ptr<Prism::Contract::StreamFactory> Accept;
        Middleware::Context *Context;
        std::string *Response;
        std::string *Prefix;
    };

    auto RunHttpConnect(HttpConnectRequest Request) -> Net::awaitable<void>
    {
        const std::string Wire = "CONNECT example.com:443 HTTP/1.1\r\n"
                                  "Host: example.com:443\r\n"
                                  "\r\n"
                                  "tunnel-prefix";
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Wire));
        Error = Prism::Fault::ToNative(Write.Failure);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        auto Accepted = co_await Request.Accept->Accept(
            Prism::Testing::MakeAdapterAcceptInput(Request.Inbound));
        const auto Code = Accepted ? Fault::Code::Success
            : Accepted.error().Code;
        if (Accepted)
        {
            Request.Context->SetDataPlane(std::move(*Accepted));
            Request.Inbound = Request.Context->Inbound();
        }
        if (Code != Fault::Code::Success || !Request.Context->PostDial())
        {
            ADD_FAILURE() << "HTTP CONNECT accept did not produce a post-dial callback";
            co_return;
        }
        const auto PostDialFailure = co_await Request.Context->PostDial()(Fault::Failure{});
        EXPECT_TRUE(PostDialFailure.Succeeded());
        std::array<std::byte, 128> ResponseBuffer{};
        const auto ResponseRead = co_await Request.Client->ReadSome(ResponseBuffer);
        Error = Prism::Fault::ToNative(ResponseRead.Failure);
        const auto ResponseSize = ResponseRead.Bytes;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Request.Response->assign(
            reinterpret_cast<const char *>(ResponseBuffer.data()), ResponseSize);
        std::array<std::byte, 64> PrefixBuffer{};
        const auto PrefixRead = co_await Request.Inbound->ReadSome(PrefixBuffer);
        Error = Prism::Fault::ToNative(PrefixRead.Failure);
        const auto PrefixSize = PrefixRead.Bytes;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Request.Prefix->assign(reinterpret_cast<const char *>(PrefixBuffer.data()), PrefixSize);
    }

    struct HttpForwardRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        SharedTransmission Inbound;
        std::shared_ptr<Prism::Contract::StreamFactory> Accept;
        Middleware::Context *Context;
        std::string *Forwarded;
    };

    auto RunHttpForward(HttpForwardRequest Request) -> Net::awaitable<void>
    {
        const std::string Wire = "POST http://example.com/upload HTTP/1.1\r\n"
                                  "Host: example.com\r\n"
                                  "Content-Length: 7\r\n"
                                  "\r\n"
                                  "payload";
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Wire));
        Error = Prism::Fault::ToNative(Write.Failure);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        auto Accepted = co_await Request.Accept->Accept(
            Prism::Testing::MakeAdapterAcceptInput(Request.Inbound));
        const auto Code = Accepted ? Fault::Code::Success
            : Accepted.error().Code;
        if (Accepted)
        {
            Request.Context->SetDataPlane(std::move(*Accepted));
            Request.Inbound = Request.Context->Inbound();
        }
        if (Code != Fault::Code::Success || !Request.Context->PostDial())
        {
            ADD_FAILURE() << "HTTP absolute-form accept did not complete";
            co_return;
        }
        const auto PostDialFailure = co_await Request.Context->PostDial()(Fault::Failure{});
        EXPECT_TRUE(PostDialFailure.Succeeded());
        EXPECT_EQ(Request.Context->Target().Host, *Prism::Network::ParseHost("example.com"));
        EXPECT_EQ(Request.Context->Target().Port, 80);
        std::array<std::byte, 256> Buffer{};
        const auto Read = co_await Request.Inbound->ReadSome(Buffer);
        Error = Prism::Fault::ToNative(Read.Failure);
        const auto ForwardedSize = Read.Bytes;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Request.Forwarded->assign(reinterpret_cast<const char *>(Buffer.data()), ForwardedSize);
    }

    struct HttpAuthRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        SharedTransmission Inbound;
        std::shared_ptr<Prism::Contract::StreamFactory> Accept;
        Middleware::Context *Context;
        std::string *Response;
        Fault::Code *Code;
    };

    /** @brief 读取关闭响应直到 EOF；拒绝响应远小于内部缓冲区，不使用固定长度成功条件。 */
    auto ReadHttpResponse(const std::shared_ptr<MemoryStream> &Client)
        -> Net::awaitable<std::string>
    {
        std::array<std::byte, 256> Buffer{};
        std::string Response;
        for (;;)
        {
            const auto Read = co_await Client->ReadSome(Buffer);
            if (Read.Bytes != 0U)
            {
                Response.append(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes);
            }
            if (Read.Failure.Failed())
            {
                co_return Response;
            }
        }
    }

    auto RunHttpAuth(HttpAuthRequest Request) -> Net::awaitable<void>
    {
        const std::string Wire = "CONNECT example.com:443 HTTP/1.1\r\n"
                                  "Host: example.com:443\r\n"
                                  "Proxy-Authorization: Basic dXNlcjpiYWQ=\r\n"
                                  "\r\n";
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Wire));
        Error = Prism::Fault::ToNative(Write.Failure);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        auto Accepted = co_await Request.Accept->Accept(
            Prism::Testing::MakeAdapterAcceptInput(Request.Inbound));
        *Request.Code = Accepted ? Fault::Code::Success
            : Accepted.error().Code;
        if (Accepted)
        {
            Request.Context->SetDataPlane(std::move(*Accepted));
            Request.Inbound = Request.Context->Inbound();
        }
        *Request.Response = co_await ReadHttpResponse(Request.Client);
        if (Request.Response->empty())
        {
            ADD_FAILURE() << "HTTP proxy rejection response was empty";
        }
    }

    template <typename Handler>
    struct CredentialAdmissionRequest final
    {
        Handler *HandlerValue;
        std::shared_ptr<MemoryStream> Client;
        Prism::Contract::StreamAcceptInput Input;
        std::vector<std::byte> Wire;
        Prism::Contract::AcceptOutcome *Result;
    };

    /**
     * @brief 将协议 builder 的 uint8_t wire 复制为请求拥有的 byte 缓冲。
     * @param Wire builder 产生的只读 wire。
     * @return 独立拥有的 byte wire。
     */
    auto CopyWireBytes(std::span<const std::uint8_t> Wire) -> std::vector<std::byte>
    {
        std::vector<std::byte> Result;
        Result.reserve(Wire.size());
        for (const auto Byte : Wire)
        {
            Result.push_back(static_cast<std::byte>(Byte));
        }
        return Result;
    }

    template <typename Handler>
    auto RunCredentialAdmission(CredentialAdmissionRequest<Handler> Request)
        -> Net::awaitable<void>
    {
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteSome(std::span<const std::byte>(Request.Wire));
        Error = Prism::Fault::ToNative(Write.Failure);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        *Request.Result = co_await Request.HandlerValue->Accept(std::move(Request.Input));
    }

    struct ContextTransferRequest final
    {
        std::shared_ptr<Prism::Contract::StreamFactory> Accept;
        SharedTransmission *Transport;
        Middleware::Context *Context;
    };

    auto RunContextTransfer(ContextTransferRequest Request) -> Net::awaitable<void>
    {
        auto Accepted = co_await Request.Accept->Accept(
            Prism::Testing::MakeAdapterAcceptInput(*Request.Transport));
        const auto Code = Accepted ? Fault::Code::Success
            : Accepted.error().Code;
        if (Accepted)
        {
            Request.Context->SetDataPlane(std::move(*Accepted));
            *Request.Transport = Request.Context->Inbound();
        }
        EXPECT_EQ(Code, Fault::Code::Success);
    }

    auto RunSessionRejectsSuccessWithoutTransport(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto [Client, Inbound] = MakePairShared(IoContext);
        Prism::Contract::ProtocolDataPlane Plane;
        auto Accept = MakeStubAccept(std::move(Plane));
        Runtime::SessionOptions Options;
        Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Options.Services->AcceptProtocol = Accept;
        Runtime::Session Session(std::move(Options));
        const auto Code = (co_await Session.Run(Inbound)).Code;
        EXPECT_EQ(Code, Fault::Code::IoError);
        (void)Client;
    }

    auto BuildVmessWire(const std::array<std::uint8_t, 16> &Uuid)
        -> std::vector<std::uint8_t>
    {
        Prism::Vmess::Message Message;
        Message.uuid = Uuid;
        Message.RequestNonce.fill(0x31);
        Message.RequestKey.fill(0x42);
        Message.Cmd = Prism::Vmess::CmdTcp;
        Message.dst = Prism::Vmess::Address{
            Prism::Vmess::AddressType::Domain, "account.example", 443};
        Prism::Vmess::Serializer Serializer(Uuid);
        Serializer.Reset(
            Message,
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                           std::chrono::system_clock::now().time_since_epoch())
                                           .count()));
        std::array<std::uint8_t, 512> Buffer{};
        std::error_code ErrorCode;
        const auto WireSize = Serializer.Get(
            Net::mutable_buffer(Buffer.data(), Buffer.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Serializer.IsDone());
        Prism::Vmess::Parser Parser(Uuid);
        Parser.Put(Net::const_buffer(Buffer.data(), WireSize), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        return {Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(WireSize)};
    }

    auto BuildSs2022Wire(const std::array<std::uint8_t, 16> &Psk)
        -> std::vector<std::byte>
    {
        const auto Wire = Prism::Testing::RecognitionWire::MakeSs2022(Psk);
        std::error_code ErrorCode;
        Prism::Shadowsocks2022::Parser Parser(Psk);
        Parser.Put(Net::const_buffer(Wire.data(), Wire.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        return Wire;
    }
}

TEST(AdapterSeam, FillContext)
{
    Net::io_context IoContext;
    RunCoro(IoContext, RunFillContext(IoContext));
}

TEST(AdapterSeam, HttpConnectReplyWaitsForDialAndKeepsTunnelPrefix)
{
    Net::io_context Io;
    auto [Client, Server] = MakePairShared(Io);
    auto HttpOwner = Prism::Testing::MakeAdapterHttpBinding(
        Prism::Testing::ProviderAccountInput{
            Prism::AccountId{1}, Prism::Account::Credential::Password("unused"),
            "user", "user", {}},
        false, Io.get_executor());
    auto Binding = Prism::Composition::Recognition::CandidateFactory::MakeHttp(
        Prism::Composition::Recognition::CandidateOptions{1, "http", 0, 0, false},
        std::move(HttpOwner));
    Middleware::Context Context;
    std::string Response;
    std::string Prefix;
    RunCoro(Io, RunHttpConnect(HttpConnectRequest{
        Client, Server, Binding.Accept, &Context, &Response, &Prefix}));
    EXPECT_EQ(Response, "HTTP/1.1 200 Connection Established\r\n\r\n");
    EXPECT_EQ(Prefix, "tunnel-prefix");
}

TEST(AdapterSeam, HttpAbsoluteFormForwardsOriginFormWithoutProxyResponse)
{
    Net::io_context Io;
    auto [Client, Server] = MakePairShared(Io);
    auto HttpOwner = Prism::Testing::MakeAdapterHttpBinding(
        Prism::Testing::ProviderAccountInput{
            Prism::AccountId{1}, Prism::Account::Credential::Password("unused"),
            "user", "user", {}},
        false, Io.get_executor());
    auto Binding = Prism::Composition::Recognition::CandidateFactory::MakeHttp(
        Prism::Composition::Recognition::CandidateOptions{1, "http", 0, 0, false},
        std::move(HttpOwner));
    Middleware::Context Context;
    std::string Forwarded;
    RunCoro(Io, RunHttpForward(HttpForwardRequest{
        Client, Server, Binding.Accept, &Context, &Forwarded}));
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
    auto HttpOwner = Prism::Testing::MakeAdapterHttpBinding(
        Prism::Testing::ProviderAccountInput{
            Prism::AccountId{1U}, Prism::Account::Credential::Password("pass"),
            "user", "user", {}},
        true, Io.get_executor());
    auto Binding = Prism::Composition::Recognition::CandidateFactory::MakeHttp(
        Prism::Composition::Recognition::CandidateOptions{17, "http-auth", 0, 0, false},
        std::move(HttpOwner));
    Middleware::Context Context;
    std::string Response;
    Fault::Code Code = Fault::Code::Success;
    RunCoro(Io, RunHttpAuth(HttpAuthRequest{
        Client, Server, Binding.Accept, &Context, &Response, &Code}));
    EXPECT_EQ(Code, Fault::Code::AuthFailed);
    EXPECT_TRUE(Response.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
}

TEST(AdapterSeam, VlessStaticCredentialMapsSyntheticAccountLease)
{
    Net::io_context Io;
    auto [Client, Server] = MakePairShared(Io);
    const auto OriginalTransport = Server;
    const std::array<std::uint8_t, Prism::Vless::UuidLen> Uuid{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    Prism::Account::UuidBytes CredentialBytes{};
    for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
    {
        CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
    }
    auto Directory = Prism::Testing::ProviderAccount(
        Prism::Account::Credential::Uuid(CredentialBytes), Prism::AccountId{1U}, {});
    Prism::Vless::ServerConfig Config;
    Config.AuthenticatorOwner = Directory->Authenticator;
    auto Handler = Prism::Testing::MakeAdapterVlessIngress(
        Config, Directory, Io.get_executor());
    Prism::Contract::AcceptOutcome Result{std::unexpected(Prism::Contract::FailureFromProtocolError(Error::NotOpen))};
    Prism::Vless::RequestHeader Request;
    Request.Uuid = Uuid;
    Request.Cmd = Prism::Vless::Command::Tcp;
    Request.Target = Prism::Vless::Address{
        Prism::Vless::AddressType::Domain, "example.com", 443};
    const auto Wire = Prism::Vless::BuildRequest(Request);
    RunCoro(Io, RunCredentialAdmission(
        CredentialAdmissionRequest<Prism::Vless::IngressFactory>{
            Handler.get(), Client,
            Prism::Testing::MakeAdapterAcceptInput(Server, Handler->GenerationUseState()),
            CopyWireBytes(std::span<const std::uint8_t>(Wire)), &Result}));

        ASSERT_TRUE(Result);
        EXPECT_TRUE(Result->ProtocolAuthenticated);
        ASSERT_TRUE(Result->AccountLease);
        EXPECT_EQ(Result->AccountId, Prism::AccountId{1});
        const auto AccountBinding = Result->AccountLease.Binding();
        ASSERT_NE(AccountBinding, nullptr);
        EXPECT_EQ(AccountBinding->AccountId(), Result->AccountId);
        EXPECT_EQ(AccountBinding->Runtime()->ActiveConnections(), 1U);
        ASSERT_TRUE(Result->HasTransport());
        const auto TypedTransport = Result->Transport();
        ASSERT_TRUE(TypedTransport);
        EXPECT_EQ(TypedTransport->NextLayer(), OriginalTransport.get());
        (void)TypedTransport->Close();
        Result->AccountLease.Release();
        EXPECT_FALSE(Result->AccountLease);
        EXPECT_EQ(AccountBinding->Runtime()->ActiveConnections(), 0U);
}

TEST(AdapterSeam, TrojanStaticCredentialMapsSyntheticAccountLease)
{
    Net::io_context Io;
    auto [Client, Server] = MakePairShared(Io);
    const auto OriginalTransport = Server;
    const auto Credential = Prism::Trojan::Credential("static-secret");
    auto Directory = Prism::Testing::ProviderAccount(
        Prism::Account::Credential::Token(Credential), Prism::AccountId{1U}, {});
    Prism::Trojan::ServerConfig Config;
    Config.Password = "different-config-password";
    Config.AuthenticatorOwner = Directory->Authenticator;
    auto Handler = Prism::Testing::MakeAdapterTrojanIngress(
        Config, Directory, Io.get_executor());
    Prism::Contract::AcceptOutcome Result{std::unexpected(Prism::Contract::FailureFromProtocolError(Error::NotOpen))};
    const auto Wire = Prism::Trojan::BuildRequest(
        Credential,
        Prism::Trojan::Command::Connect,
        Prism::Trojan::Address{
            Prism::Trojan::AddressType::Domain, "example.com", 443});
    RunCoro(Io, RunCredentialAdmission(
        CredentialAdmissionRequest<Prism::Trojan::IngressFactory>{
            Handler.get(), Client,
            Prism::Testing::MakeAdapterAcceptInput(Server, Handler->GenerationUseState()),
            CopyWireBytes(std::span<const std::uint8_t>(Wire)), &Result}));

        ASSERT_TRUE(Result);
        EXPECT_TRUE(Result->ProtocolAuthenticated);
        ASSERT_TRUE(Result->AccountLease);
        EXPECT_EQ(Result->AccountId, Prism::AccountId{1});
        const auto AccountBinding = Result->AccountLease.Binding();
        ASSERT_NE(AccountBinding, nullptr);
        EXPECT_EQ(AccountBinding->AccountId(), Result->AccountId);
        EXPECT_EQ(AccountBinding->Runtime()->ActiveConnections(), 1U);
        ASSERT_TRUE(Result->HasTransport());
        const auto TypedTransport = Result->Transport();
        ASSERT_TRUE(TypedTransport);
        EXPECT_EQ(TypedTransport->NextLayer(), OriginalTransport.get());
        (void)TypedTransport->Close();
        Result->AccountLease.Release();
        EXPECT_FALSE(Result->AccountLease);
        EXPECT_EQ(AccountBinding->Runtime()->ActiveConnections(), 0U);
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
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Uuid(CredentialBytes), Prism::AccountId{7101},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Prism::AccountId{7101});
        ASSERT_TRUE(Record);
        auto ProbeAuthenticator = Directory->Authenticator;
        auto ProbeResult = ProbeAuthenticator->Authenticate(Prism::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Prism::Account::CredentialView{
                Prism::Account::CredentialKind::Uuid,
                std::as_bytes(std::span<const std::uint8_t>(Uuid))},
            .Rate = {}});
        ASSERT_TRUE(ProbeResult);
        ProbeResult->Release();
        Prism::Vmess::ServerConfig Config;
        auto Handler = Prism::Testing::MakeAdapterVmessIngress(
            Config, Directory, Io.get_executor());
        Prism::Contract::AcceptOutcome Result{std::unexpected(Prism::Contract::FailureFromProtocolError(Error::NotOpen))};
        const auto Wire = BuildVmessWire(Uuid);
        ASSERT_FALSE(Wire.empty());
        RunCoro(Io, RunCredentialAdmission(
            CredentialAdmissionRequest<Prism::Vmess::IngressFactory>{
                Handler.get(), Client,
                Prism::Testing::MakeAdapterAcceptInput(Server, Handler->GenerationUseState()),
                CopyWireBytes(std::span<const std::uint8_t>(Wire)), &Result}));

        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->AccountId, Prism::AccountId{7101});
        ASSERT_TRUE(Result->AccountLease);
        EXPECT_TRUE(static_cast<bool>(Result->AccountLease));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Result->AccountLease.Release();
        EXPECT_FALSE(static_cast<bool>(Result->AccountLease));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        const auto Transport = Result->Transport();
        ASSERT_TRUE(Transport);
        Io.restart();
        RunCoro(Io, [Transport, &Result]() -> Net::awaitable<void>
        {
            const auto Receipt = co_await Prism::Testing::CloseFixture(Transport);
            Prism::Testing::ExpectFixtureCloseReceipt(Receipt);
            EXPECT_FALSE(Transport->IsOpen());
            EXPECT_FALSE(Result->Transport()->IsOpen());
        }());
    }

TEST(AdapterSeam, Ss2022DirectoryCredentialMapsAccountLease)
    {
        Net::io_context Io;
        auto [Client, Server] = MakePairShared(Io);
        const std::array<std::uint8_t, 16> Psk{
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70};
        const std::string PskBytes(reinterpret_cast<const char *>(Psk.data()), Psk.size());
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Psk(PskBytes), Prism::AccountId{7102},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Prism::AccountId{7102});
        ASSERT_TRUE(Record);
        auto ProbeAuthenticator = Directory->Authenticator;
        auto ProbeResult = ProbeAuthenticator->Authenticate(Prism::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Prism::Account::CredentialView::Psk(PskBytes),
            .Rate = {}});
        ASSERT_TRUE(ProbeResult);
        ProbeResult->Release();
        Prism::Shadowsocks2022::ServerConfig Config;
        auto Handler = Prism::Testing::MakeSs2022Binding(Config, Directory);
        Prism::Contract::AcceptOutcome Result{std::unexpected(Prism::Contract::FailureFromProtocolError(Error::NotOpen))};
        auto Wire = BuildSs2022Wire(Psk);
        ASSERT_FALSE(Wire.empty());
        RunCoro(Io, RunCredentialAdmission(
            CredentialAdmissionRequest<Prism::Shadowsocks2022::Binding>{
                Handler.get(), Client,
                Prism::Testing::MakeAdapterAcceptInput(Server), std::move(Wire), &Result}));

        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->AccountId, Prism::AccountId{7102});
        ASSERT_TRUE(Result->AccountLease);
        EXPECT_TRUE(static_cast<bool>(Result->AccountLease));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Result->AccountLease.Release();
        EXPECT_FALSE(static_cast<bool>(Result->AccountLease));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        const auto Transport = Result->Transport();
        ASSERT_TRUE(Transport);
        Io.restart();
        RunCoro(Io, [Transport, &Result]() -> Net::awaitable<void>
        {
            const auto Receipt = co_await Prism::Testing::CloseFixture(Transport);
            Prism::Testing::ExpectFixtureCloseReceipt(Receipt);
            EXPECT_FALSE(Transport->IsOpen());
            EXPECT_FALSE(Result->Transport()->IsOpen());
        }());
    }

TEST(AdapterSeam, TransfersProtocolAccountLeaseToContext)
    {
        Net::io_context Io;
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("credential"), Prism::AccountId{7003},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Prism::AccountId{7003});
        ASSERT_TRUE(Record);
        auto Authenticator = Directory->Authenticator;
        auto AuthResult = Authenticator->Authenticate(Prism::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Prism::Account::CredentialView::Password("credential"),
            .Rate = {}});
        ASSERT_TRUE(AuthResult);
        ASSERT_TRUE(*AuthResult);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);

        Prism::Contract::ProtocolDataPlane Result;
        Result.ProtocolAuthenticated = true;
        Result.AccountId = AuthResult->AccountId();
        Result.AccountLease = std::move(*AuthResult);
        auto [Client, Inbound] = MakePairShared(Io);
        Result.Root = Prism::Contract::StreamDataPlane{Client};
        auto Accept = MakeStubAccept(std::move(Result));

        Middleware::Context Context;
        SharedTransmission Transport = Inbound;
        RunCoro(Io, RunContextTransfer(ContextTransferRequest{
            Accept, &Transport, &Context}));

        EXPECT_TRUE(Context.ProtocolAuthenticated());
        EXPECT_EQ(Context.AccountId(), Prism::AccountId{7003});
        EXPECT_TRUE(Context.AccountLease());
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Context.AccountLease().Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
    }

TEST(AdapterSeam, TransfersTypedStreamAccountLeaseToContext)
    {
        Net::io_context Io;
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("credential"), Prism::AccountId{7004},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Prism::AccountId{7004});
        ASSERT_TRUE(Record);
        auto Authenticator = Directory->Authenticator;
        auto AuthResult = Authenticator->Authenticate(Prism::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Prism::Account::CredentialView::Password("credential"),
            .Rate = {}});
        ASSERT_TRUE(AuthResult);
        ASSERT_TRUE(*AuthResult);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);

        Prism::Contract::ProtocolDataPlane Result;
        Result.ProtocolAuthenticated = true;
        Result.AccountId = AuthResult->AccountId();
        Result.AccountLease = std::move(*AuthResult);
        auto [Client, Inbound] = MakePairShared(Io);
        Result.Root = Prism::Contract::StreamDataPlane{Client};
        ASSERT_TRUE(Result.HasTransport());
        auto Accept = MakeStubAccept(std::move(Result));

        Middleware::Context Context;
        SharedTransmission Transport = Inbound;
        RunCoro(Io, RunContextTransfer(ContextTransferRequest{
            Accept, &Transport, &Context}));

        EXPECT_TRUE(Context.ProtocolAuthenticated());
        EXPECT_EQ(Context.AccountId(), Prism::AccountId{7004});
        EXPECT_TRUE(Context.AccountLease());
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Context.AccountLease().Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
    }

TEST(AdapterSeam, SessionRejectsSuccessWithoutTransport)
{
    Net::io_context IoContext;
    RunCoro(IoContext, RunSessionRejectsSuccessWithoutTransport(IoContext));
}

TEST(AdapterSeam, AdmissionRetirementPreservesNativeFailureAfterDrain)
{
    Net::io_context Io;
    auto [Client, Server] = MakePairShared(Io);
    auto State = std::make_shared<AdmissionRetireRun>();
    State->Client = std::move(Client);
    State->Server = std::move(Server);
    State->Cause = Fault::Failure{
        Fault::Code::AuthFailed, std::make_error_code(std::errc::permission_denied)};

    RunCoro(Io, RunAdmissionRetirement(State));

    ASSERT_TRUE(State->Prepared);
    EXPECT_EQ(State->Result.Code, Fault::Code::AuthFailed);
    EXPECT_EQ(State->Result.Native, std::make_error_code(std::errc::permission_denied));
    EXPECT_TRUE(State->Drained);
}
