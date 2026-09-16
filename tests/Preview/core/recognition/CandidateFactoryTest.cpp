/**
 * @file CandidateFactoryTest.cpp
 * @brief Composition 候选工厂最小行为测试（Task5 RED）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/ProfileBuilder.hpp>

#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "RecognitionWire.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;

    auto RunPrepare(Core::PrepareFn Prepare, Core::PrepareContext Context) -> Core::PrepareResult
    {
        Net::io_context Io;
        Core::PrepareResult Result;
        std::exception_ptr Failure;
        Net::co_spawn(Io, Prepare(std::move(Context)),
                      [&Result, &Failure, &Io](std::exception_ptr Error, Core::PrepareResult Value)
                      {
                          Failure = std::move(Error);
                          if (!Failure)
                          {
                              Result = std::move(Value);
                          }
                          Io.stop();
                      });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
        return Result;
    }

} // namespace

TEST(CandidateFactory, CreatesSocks5Binding)
{
    Preview::Socks5::ServerConfig Config;
    const auto Binding = Composition::CandidateFactory::MakeSocks5(
        Composition::CandidateOptions{7, "edge-socks", 2, 1}, Config);

    EXPECT_EQ(Binding.Spec.Id, 7);
    EXPECT_EQ(Binding.Spec.Name, "edge-socks");
    EXPECT_EQ(Binding.Spec.Protocol, Preview::Recognition::ProtocolType::Socks5);
    EXPECT_TRUE(Binding.Accept);
    EXPECT_TRUE(Binding.Spec.Inspect);
    EXPECT_TRUE(Binding.Spec.Commit);
}

TEST(CandidateFactory, RejectsBindingWithoutResolver)
{
    auto Binding = Composition::CandidateFactory::MakeHttp(8);
    Binding.Accept = {};

    auto Built = Composition::ProfileBuilder::Build(std::move(Binding));

    EXPECT_FALSE(Built.has_value());
}

TEST(CandidateFactory, RejectsUnbracketedIpv6HttpAuthority)
{
    const auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
    const std::string Request = "CONNECT 2001:db8::1:443 HTTP/1.1\r\n"
                                "Host: 2001:db8::1:443\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    const auto State = Binding.Spec.Inspect(Preview::Recognition::ProbeSnapshot{Storage});

    EXPECT_EQ(State, Preview::Recognition::MatchState::Rejected);
}

TEST(CandidateFactory, RejectsNonIpv6BracketedHttpAuthority)
{
    const auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
    const std::string Request = "CONNECT [not-an-ip]:443 HTTP/1.1\r\n"
                                "Host: [not-an-ip]:443\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    const auto State = Binding.Spec.Inspect(Preview::Recognition::ProbeSnapshot{Storage});

    EXPECT_EQ(State, Preview::Recognition::MatchState::Rejected);
}

TEST(CandidateFactory, AcceptsValidBracketedIpv6HttpAuthority)
{
    const auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
    const std::string Request = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"
                                "Host: [2001:db8::1]:443\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    const auto State = Binding.Spec.Inspect(Preview::Recognition::ProbeSnapshot{Storage});

    EXPECT_EQ(State, Preview::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, RecognizesAbsoluteFormHttpProxyRequests)
{
    const auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
    const std::string Request = "POST http://example.com/upload HTTP/1.1\r\n"
                                "Host: example.com\r\n"
                                "Content-Length: 7\r\n"
                                "\r\n"
                                "payload";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    EXPECT_EQ(Binding.Spec.Inspect(Preview::Recognition::ProbeSnapshot{Storage}),
              Preview::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, DoesNotRecognizeHttpResponseAsInboundProxyRequest)
{
    const auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
    const std::string Response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Response.size());
    for (const auto Character : Response)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    EXPECT_EQ(Binding.Spec.Inspect(Preview::Recognition::ProbeSnapshot{Storage}),
              Preview::Recognition::MatchState::Rejected);
}

TEST(CandidateFactory, RejectsAuthenticatedVmessUnknownCommand)
{
    constexpr std::array<std::uint8_t, 16> Uuid{
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};
    Preview::Vmess::Message Message;
    Message.Cmd = 0x99;
    Message.dst.Type = Preview::Vmess::AddressType::Domain;
    Message.dst.Host = "example.com";
    Message.dst.Port = 443;
    Message.RequestNonce.fill(0x11);
    Message.RequestKey.fill(0x22);
    Message.RespHeader = 0x42;
    Preview::Vmess::Serializer Serializer(Uuid);
    Serializer.Reset(Message, static_cast<std::uint64_t>(
                                  std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count()));
    std::array<std::uint8_t, 1024> Wire{};
    std::error_code SerializeError;
    const auto Size = Serializer.Get(boost::asio::mutable_buffer(Wire.data(), Wire.size()), SerializeError);
    ASSERT_FALSE(SerializeError);

    auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeVmess(
        Preview::Composition::Recognition::CandidateOptions{7, "vmess", 0, 0, false},
        Preview::Vmess::ServerConfig{Uuid});
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Size);
    for (std::size_t Index = 0; Index < Size; ++Index)
    {
        Storage->push_back(static_cast<std::byte>(Wire[Index]));
    }

    Preview::Recognition::PrepareResult Result;
    boost::asio::io_context Io;
    Preview::Recognition::PrepareContext Context;
    Context.Candidate = 7;
    Context.Snapshot = Preview::Recognition::ProbeSnapshot{Storage};
    boost::asio::co_spawn(
        Io, Binding.Spec.Prepare(std::move(Context)),
        [&Io, &Result](std::exception_ptr Error, Preview::Recognition::PrepareResult Value)
        {
            if (!Error)
            {
                Result = std::move(Value);
            }
            Io.stop();
        });
    Io.run();

    EXPECT_EQ(Result.Status, Preview::Recognition::RecognitionStatus::NoMatch);
}

TEST(CandidateFactory, VlessPrepareOwnsAuthenticatorAcrossConfigLifetime)
{
    const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(41);
    const std::string Secret(reinterpret_cast<const char *>(Uuid.data()), Uuid.size());
    auto Owner = std::make_shared<Preview::StaticAuthenticator>("", Secret);
    Preview::Vless::ServerConfig Config;
    Config.uuid = Uuid;
    Config.Authenticator = Owner.get();
    Config.AuthenticatorOwner = Owner;
    auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeVless(
        Preview::Composition::Recognition::CandidateOptions{41, "owned-vless", 0, 0, false}, Config);
    Owner.reset();

    auto Storage = std::make_shared<const std::vector<std::byte>>(
        Preview::Testing::RecognitionWire::MakeVless(Uuid));
    Core::PrepareContext Context;
    Context.Candidate = Binding.Spec.Id;
    Context.Snapshot = Core::ProbeSnapshot{Storage};
    const auto Result = RunPrepare(Binding.Spec.Prepare, std::move(Context));

    EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
}

TEST(CandidateFactory, TrojanPrepareOwnsAuthenticatorAcrossConfigLifetime)
{
    auto Owner = std::make_shared<Preview::StaticAuthenticator>(
        "", Preview::Trojan::Credential("trojan-owned"));
    Preview::Trojan::ServerConfig Config;
    Config.password = "unused-static-password";
    Config.Authenticator = Owner.get();
    Config.AuthenticatorOwner = Owner;
    auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeTrojan(
        Preview::Composition::Recognition::CandidateOptions{42, "owned-trojan", 0, 0, false}, Config);
    Owner.reset();

    auto Storage = std::make_shared<const std::vector<std::byte>>(
        Preview::Testing::RecognitionWire::MakeTrojan("trojan-owned"));
    Core::PrepareContext Context;
    Context.Candidate = Binding.Spec.Id;
    Context.Snapshot = Core::ProbeSnapshot{Storage};
    const auto Result = RunPrepare(Binding.Spec.Prepare, std::move(Context));

    EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
}

TEST(CandidateFactory, VlessConnectionRetainsAuthenticatorOwner)
{
    const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(43);
    auto Owner = std::make_shared<Preview::StaticAuthenticator>("", "connection-secret");
    const std::weak_ptr<Preview::Authenticator> WeakOwner = Owner;
    auto Connection = std::make_shared<Preview::Vless::Conn<>>(
        Preview::SharedTransmission{}, Uuid, Owner.get(), Owner);

    Owner.reset();
    EXPECT_FALSE(WeakOwner.expired());
    Connection.reset();
    EXPECT_TRUE(WeakOwner.expired());
}

TEST(CandidateFactory, TrojanConnectionRetainsAuthenticatorOwner)
{
    auto Owner = std::make_shared<Preview::StaticAuthenticator>("", "connection-secret");
    const std::weak_ptr<Preview::Authenticator> WeakOwner = Owner;
    auto Connection = std::make_shared<Preview::Trojan::Conn<>>(
        Preview::SharedTransmission{}, "password", Owner.get(), Owner);

    Owner.reset();
    EXPECT_FALSE(WeakOwner.expired());
    Connection.reset();
    EXPECT_TRUE(WeakOwner.expired());
}
