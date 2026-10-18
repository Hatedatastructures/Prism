#include <TestSupport/Fixtures/StreamFactory.hpp>
/**
 * @file AdapterMuxLeaseTest.cpp
 * @brief 协议 mux adapter 的真实握手与账户租约生命周期测试。
 */

#include <gtest/gtest.h>
#include <TestSupport/Fixtures/StreamFactory.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <Prism/Account/Account.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Protocols/Anytls/Anytls.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Middleware = Prism::Middleware;
    namespace Runtime = Prism::Runtime;

    using Prism::Error;
    using Prism::MemoryStream;
    using Prism::SharedTransmission;
    using Prism::Testing::RunCoro;
    namespace Fault = Prism::Fault;

    template <typename Buffer>
    auto WireBytes(const Buffer &Value) -> std::span<const std::byte>
    {
        using Element = typename Buffer::value_type;
        const std::span<const Element> Bytes(Value.data(), Value.size());
        return std::as_bytes(Bytes);
    }

    struct AdapterDriveRequest final
    {
        std::shared_ptr<Prism::Contract::StreamFactory> Handler;
        SharedTransmission Inbound;
        std::shared_ptr<MemoryStream> Client;
        std::span<const std::byte> Wire;
        Middleware::Context *Context;
        Fault::Code *Code;
    };

    auto RunAdapterDrive(AdapterDriveRequest Request) -> Net::awaitable<void>
    {
        const auto Written = co_await Request.Client->WriteExact(Request.Wire);
        if (Written.Failure.Failed())
        {
            ADD_FAILURE() << "mux request write failed: "
                          << Fault::ToNative(Written.Failure).message();
            co_return;
        }
        if (Written.Bytes != Request.Wire.size())
        {
            ADD_FAILURE() << "mux request write incomplete: " << Written.Bytes
                          << "/" << Request.Wire.size();
            co_return;
        }
        auto Accepted = co_await Request.Handler->Accept(Request.Inbound, {});
        *Request.Code = Accepted ? Fault::Code::Success
            : Fault::ToCode(Prism::make_error_code(Accepted.error()));
        if (Accepted)
        {
            Request.Context->SetDataPlane(std::move(*Accepted));
            Request.Inbound = Request.Context->Inbound();
        }
    }

    struct AnytlsHandshakeRequest final
    {
        std::shared_ptr<Prism::Anytls::IngressFactory> Handler;
        SharedTransmission Inbound;
        std::shared_ptr<MemoryStream> Client;
        Middleware::Context *Context;
        Fault::Code *Code;
    };

    auto RunAnytlsHandshake(AnytlsHandshakeRequest Request) -> Net::awaitable<void>
    {
        auto Connected = co_await Prism::Anytls::Connect(
            Request.Client, Prism::Anytls::ClientConfig{"mux-password"});
        if (!Connected)
        {
            ADD_FAILURE() << "AnyTLS client handshake failed";
            co_return;
        }
        auto ClientConnection = std::move(*Connected);
        auto Accepted = co_await Request.Handler->Accept(Request.Inbound, {});
        *Request.Code = Accepted ? Fault::Code::Success
            : Accepted.error().Code;
        if (Accepted)
        {
            Request.Context->SetDataPlane(std::move(*Accepted));
            Request.Inbound = Request.Context->Inbound();
        }
        ClientConnection->Close();
    }

    auto MakeAccountRecord(Prism::AccountId AccountId,
                           Prism::Account::Credential CredentialValue)
        -> std::shared_ptr<Prism::Testing::ProviderAccounts>
    {
        return Prism::Testing::ProviderAccount(
            std::move(CredentialValue), AccountId, {.MaxConnections = 1, .MaxStreams = 1});
    }

    auto MakeUuidAccountRecord(Prism::AccountId AccountId,
                               const std::array<std::uint8_t, 16> &Uuid)
        -> std::shared_ptr<Prism::Testing::ProviderAccounts>
    {
        std::array<std::byte, 16> CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        return MakeAccountRecord(
            AccountId, Prism::Account::Credential::Uuid(CredentialBytes));
    }

    class AdapterMuxLeaseTest : public ::testing::Test
    {
    protected:
        AdapterMuxLeaseTest()
        {
            auto [Client, Server] = Prism::MakeMemoryPair(Io_.get_executor());
            Client_ = std::make_shared<MemoryStream>(std::move(Client));
            Server_ = std::make_shared<MemoryStream>(std::move(Server));
        }

        auto Drive(std::shared_ptr<Prism::Contract::StreamFactory> Handler,
                   std::span<const std::byte> Wire) -> Fault::Code
        {
            auto Code = Fault::Code::IoError;
            RunCoro(Io_, RunAdapterDrive(AdapterDriveRequest{
                std::move(Handler), Server_, Client_, Wire, &Context_, &Code}));
            return Code;
        }

        auto ExpectLeaseLifecycle() -> void
        {
            ASSERT_TRUE(Record_);
            EXPECT_TRUE(Context_.DataPlane.IsMux());
            ASSERT_TRUE(static_cast<bool>(Context_.AccountLease()));
            EXPECT_EQ(&Context_.AccountLease(), &Context_.DataPlane.AccountLease);
            EXPECT_EQ(Record_->Runtime()->ActiveConnections(), 1U);

            auto Child = Context_.AccountLease().TryAcquireStream();
            ASSERT_TRUE(static_cast<bool>(Child));
            EXPECT_EQ(Record_->Runtime()->ActiveStreams(), 1U);
            auto OverQuota = Context_.AccountLease().TryAcquireStream();
            EXPECT_FALSE(static_cast<bool>(OverQuota));

            Child.Release();
            EXPECT_EQ(Record_->Runtime()->ActiveStreams(), 0U);
            EXPECT_EQ(Record_->Runtime()->ActiveConnections(), 1U);
            auto Replacement = Context_.AccountLease().TryAcquireStream();
            ASSERT_TRUE(static_cast<bool>(Replacement));
            Replacement.Release();

            const auto Transport = Context_.DataPlane.Transport();
            ASSERT_TRUE(Transport);
            Transport->Close();
            Transport->Close();
            EXPECT_EQ(Record_->Runtime()->ActiveConnections(), 1U);
            if (Context_.Inbound()) Context_.Inbound()->Close();
            Context_.SetDataPlane({});
            EXPECT_EQ(Record_->Runtime()->ActiveConnections(), 0U);
            if (Context_.Inbound()) Context_.Inbound()->Close();
            Context_.SetDataPlane({});
            EXPECT_EQ(Record_->Runtime()->ActiveConnections(), 0U);
        }

        Net::io_context Io_;
        std::shared_ptr<MemoryStream> Client_;
        std::shared_ptr<MemoryStream> Server_;
        Middleware::Context Context_;
        std::shared_ptr<const Prism::Account::AccountBinding> Record_;
    };

    TEST_F(AdapterMuxLeaseTest, TrojanMuxAdapterKeepsAccountLeaseUntilContextClose)
    {
        const std::string Password = "trojan-mux-password";
        const auto Credential = Prism::Trojan::Credential(Password);
        auto Directory = MakeAccountRecord(
            Prism::AccountId{7111}, Prism::Account::Credential::Token(Credential));
        Record_ = Directory->Store->FindById(Prism::AccountId{7111});
        ASSERT_TRUE(Record_);

        Prism::Trojan::ServerConfig Config;
        Config.AuthenticatorOwner = Directory->Authenticator;
        auto Handler = std::make_shared<Prism::Trojan::IngressFactory>(Prism::Trojan::IngressOptions{.Configuration = std::move(Config), .Mux = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{.Services = {.Egress = Prism::Testing::UnavailableEgress()}})});
        const auto Wire = Prism::Trojan::BuildRequest(
            Credential,
            Prism::Trojan::Command::Mux,
            Prism::Trojan::Address{
                Prism::Trojan::AddressType::Domain, "example.com", 443});

        EXPECT_EQ(Drive(std::move(Handler), WireBytes(Wire)), Fault::Code::Success);
        ExpectLeaseLifecycle();
    }

    TEST_F(AdapterMuxLeaseTest, VlessMuxAdapterKeepsAccountLeaseUntilContextClose)
    {
        const std::array<std::uint8_t, Prism::Vless::UuidLen> Uuid{
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
            0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80};
        auto Directory = MakeUuidAccountRecord(Prism::AccountId{7112}, Uuid);
        Record_ = Directory->Store->FindById(Prism::AccountId{7112});
        ASSERT_TRUE(Record_);

        Prism::Vless::ServerConfig Config;
        Config.AuthenticatorOwner = Directory->Authenticator;
        auto Handler = std::make_shared<Prism::Vless::IngressFactory>(Prism::Vless::IngressOptions{.Configuration = std::move(Config)});
        Prism::Vless::RequestHeader Request;
        Request.Uuid = Uuid;
        Request.Cmd = Prism::Vless::Command::Mux;
        Request.Target = Prism::Vless::Address{
            Prism::Vless::AddressType::Domain, "example.com", 443};
        const auto Wire = Prism::Vless::BuildRequest(Request);

        EXPECT_EQ(Drive(std::move(Handler), WireBytes(Wire)), Fault::Code::Success);
        ExpectLeaseLifecycle();
    }

    TEST_F(AdapterMuxLeaseTest, VmessMuxAdapterKeepsAccountLeaseUntilContextClose)
    {
        const std::array<std::uint8_t, 16> Uuid{
            0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
            0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90};
        auto Directory = MakeUuidAccountRecord(Prism::AccountId{7113}, Uuid);
        Record_ = Directory->Store->FindById(Prism::AccountId{7113});
        ASSERT_TRUE(Record_);
        auto Handler = std::make_shared<Prism::Vmess::IngressFactory>(Prism::Vmess::IngressOptions{.Configuration = Prism::Vmess::ServerConfig{}, .Authenticator = Directory->Authenticator, .Credentials = Directory->Credentials, .Mux = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{.Services = {.Egress = Prism::Testing::UnavailableEgress()}})});

        Prism::Vmess::Message Message;
        Message.uuid = Uuid;
        Message.RequestNonce.fill(0x31);
        Message.RequestKey.fill(0x42);
        Message.Cmd = Prism::Vmess::CmdMux;
        Message.dst = Prism::Vmess::Address{
            Prism::Vmess::AddressType::Domain, "example.com", 443};
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
        ASSERT_FALSE(ErrorCode);
        ASSERT_TRUE(Serializer.IsDone());
        const auto Wire = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Buffer.data()), WireSize);

        EXPECT_EQ(Drive(std::move(Handler), Wire), Fault::Code::Success);
        ExpectLeaseLifecycle();
    }

    TEST_F(AdapterMuxLeaseTest, AnytlsMuxAdapterAcceptsRealHandshake)
    {
        auto Accept =
            std::make_shared<Prism::Anytls::IngressFactory>(Prism::Anytls::IngressOptions{.Configuration = Prism::Anytls::ServerConfig{"mux-password"}, .Streams = {.Egress = Prism::Testing::UnavailableEgress()}});
        SharedTransmission Inbound = Server_;
        auto Code = Fault::Code::IoError;
        RunCoro(Io_, RunAnytlsHandshake(
            AnytlsHandshakeRequest{std::move(Accept), Inbound, Client_, &Context_, &Code}));

        EXPECT_EQ(Code, Fault::Code::Success);
        EXPECT_TRUE(Context_.DataPlane.IsMux());
        EXPECT_TRUE(Context_.ProtocolAuthenticated());
        EXPECT_FALSE(static_cast<bool>(Context_.AccountLease()));
        const auto Transport = Context_.DataPlane.Transport();
        ASSERT_TRUE(Transport);
        Transport->Close();
        Transport->Close();
        if (Context_.Inbound()) Context_.Inbound()->Close();
            Context_.SetDataPlane({});
        if (Context_.Inbound()) Context_.Inbound()->Close();
            Context_.SetDataPlane({});
    }

    TEST_F(AdapterMuxLeaseTest, VlessMuxRejectsUnknownAccountWithoutLease)
    {
        const std::array<std::uint8_t, Prism::Vless::UuidLen> AcceptedUuid{
            0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
            0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0};
        const std::array<std::uint8_t, Prism::Vless::UuidLen> RejectedUuid{
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
            0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0};
        auto Directory = MakeUuidAccountRecord(Prism::AccountId{7114}, AcceptedUuid);
        Record_ = Directory->Store->FindById(Prism::AccountId{7114});
        ASSERT_TRUE(Record_);
        Prism::Vless::ServerConfig Config;
        Config.AuthenticatorOwner = Directory->Authenticator;
        auto Handler = std::make_shared<Prism::Vless::IngressFactory>(Prism::Vless::IngressOptions{.Configuration = std::move(Config)});
        Prism::Vless::RequestHeader Request;
        Request.Uuid = RejectedUuid;
        Request.Cmd = Prism::Vless::Command::Mux;
        Request.Target = Prism::Vless::Address{
            Prism::Vless::AddressType::Domain, "example.com", 443};
        const auto Wire = Prism::Vless::BuildRequest(Request);

        EXPECT_NE(Drive(std::move(Handler), WireBytes(Wire)), Fault::Code::Success);
        EXPECT_FALSE(Context_.DataPlane.HasTransport());
        EXPECT_FALSE(static_cast<bool>(Context_.AccountLease()));
        EXPECT_EQ(Record_->Runtime()->ActiveConnections(), 0U);
        if (Context_.Inbound()) Context_.Inbound()->Close();
            Context_.SetDataPlane({});
        EXPECT_EQ(Record_->Runtime()->ActiveConnections(), 0U);
    }
} // namespace
