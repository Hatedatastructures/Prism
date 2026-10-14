#include <TestSupport/Preview/ProtocolIngressBindings.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
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
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/ProfileBuilder.hpp>
#include <Preview/Protocols/Vless/RequestCodec.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <TestSupport/Fixtures/RecognitionWire.hpp>

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

    struct AccountRecordStore final
    {
        std::shared_ptr<Preview::Account::AccountStore> Store;
        std::vector<std::shared_ptr<const Preview::Account::AccountBinding>> Records;
    };

    auto AddAccountRecord(
        AccountRecordStore &Store,
        const Preview::AccountId AccountId,
        const std::array<std::uint8_t, 16> &Uuid) -> void
    {
        Preview::Account::UuidBytes CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        std::vector<Preview::Account::CredentialMaterial> Materials;
        Materials.push_back({Preview::Account::CredentialScope{1U}, {},
            Preview::Account::Credential::Uuid(CredentialBytes)});
        auto Owned = std::make_shared<const Preview::Account::AccountMaterials>(
            Preview::Account::AccountMaterials::CreateRequest{AccountId, {}, std::move(Materials)});
        auto Prepared = Store.Store->PrepareUpsert(Preview::Account::AccountDefinition{
            std::move(Owned), {.Quota = {.MaxConnections = 1}}});
        EXPECT_TRUE(Prepared);
        if (!Prepared)
        {
            return;
        }
        EXPECT_TRUE(Store.Store->Commit(*Prepared));
        Store.Records.push_back(Store.Store->FindById(AccountId));
    }

} // namespace

TEST(CandidateFactory, CreatesSocks5Binding)
{
    Preview::Socks5::ServerConfig Config;
    const auto Binding = Composition::CandidateFactory::MakeSocks5(
        Composition::CandidateOptions{7, "edge-socks", 2, 1}, Preview::Testing::MakeSocks5Binding(Config));

    EXPECT_EQ(Binding.Spec.Id, 7);
    EXPECT_EQ(Binding.Spec.Name, "edge-socks");
    EXPECT_EQ(Binding.Spec.Protocol, Preview::Contract::ProtocolType::Socks5);
    EXPECT_TRUE(Binding.Accept);
    EXPECT_TRUE(Binding.Spec.Inspect);
    EXPECT_TRUE(Binding.Spec.Commit);
}

TEST(CandidateFactory, RejectsBindingWithoutResolver)
{
    auto Binding = Composition::CandidateFactory::MakeHttp(Preview::Composition::Recognition::CandidateOptions{8});
    Binding.Accept = {};

    auto Built = Composition::ProfileBuilder::Build(std::move(Binding));

    EXPECT_FALSE(Built.has_value());
}

TEST(CandidateFactory, ClassifiesUnbracketedIpv6HttpAuthorityAsHttpStructure)
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

    EXPECT_EQ(State, Preview::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, ClassifiesNonIpv6BracketedHttpAuthorityAsHttpStructure)
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

    EXPECT_EQ(State, Preview::Recognition::MatchState::Structural);
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

TEST(CandidateFactory, ClassifiesUnsupportedHttpsAbsoluteFormAsHttpStructure)
{
    const auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
    const std::string Request = "GET https://example.com/private HTTP/1.1\r\n"
                                "Host: example.com\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    EXPECT_EQ(Binding.Spec.Inspect(Preview::Recognition::ProbeSnapshot{Storage}),
              Preview::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, ClassifiesLiteralFragmentTargetAsHttpStructure)
{
    const auto Binding = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
    const std::string Request = "GET /private#fragment HTTP/1.1\r\n"
                                "Host: example.com\r\n\r\n";
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

    auto Binding = Preview::Testing::MakeVmessCandidate(Preview::Composition::Recognition::CandidateOptions{7, "vmess", 0, 0, false}, Preview::Vmess::ServerConfig{Uuid});
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

TEST(CandidateFactory, VmessPrepareAcceptsAnyConfiguredDirectoryUuid)
{
    const auto FirstUuid = Preview::Testing::RecognitionWire::MakeUuid(61);
    const auto SecondUuid = Preview::Testing::RecognitionWire::MakeUuid(62);
    const auto WrongUuid = Preview::Testing::RecognitionWire::MakeUuid(63);
    AccountRecordStore Store{std::make_shared<Preview::Account::AccountStore>(), {}};
    const auto Authority = Preview::Testing::AttachAccountAdmissionAuthority(
        Store.Store->RuntimeRegistry());
    ASSERT_TRUE(Authority);
    AddAccountRecord(Store, Preview::AccountId{7061}, FirstUuid);
    AddAccountRecord(Store, Preview::AccountId{7062}, SecondUuid);

    Preview::Vmess::ServerConfig Configuration;
    Configuration.uuid = FirstUuid;
    auto View = Store.Store->CompileScope(Preview::Account::CredentialScope{1U});
    ASSERT_TRUE(View);
    auto Owner = Preview::Testing::MakeVmessProviderBinding(std::move(Configuration),
        Preview::Testing::VmessIngressResources{{}, std::move(*View), {},
            Preview::Testing::MakeProtocolIngressUseState(), boost::asio::system_executor()});
    auto Candidate = Preview::Composition::Recognition::CandidateFactory::MakeVmess(
        Preview::Composition::Recognition::CandidateOptions{61, "vmess-directory", 0, 0, false},
        std::move(Owner), std::nullopt);
    ASSERT_TRUE(Candidate);
    auto Binding = std::move(*Candidate);

    const auto Prepare = [&Binding](std::vector<std::byte> Wire)
    {
        auto Storage = std::make_shared<const std::vector<std::byte>>(std::move(Wire));
        Preview::Recognition::PrepareContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Snapshot = Preview::Recognition::ProbeSnapshot{Storage};
        return RunPrepare(Binding.Spec.Prepare, std::move(Context));
    };

    auto Tampered = Preview::Testing::RecognitionWire::MakeVmess(SecondUuid);
    ASSERT_FALSE(Tampered.empty());
    Tampered.front() ^= std::byte{0x80};

    EXPECT_EQ(Prepare(Preview::Testing::RecognitionWire::MakeVmess(FirstUuid)).Status,
              Preview::Recognition::RecognitionStatus::Accepted);
    EXPECT_EQ(Prepare(Preview::Testing::RecognitionWire::MakeVmess(SecondUuid)).Status,
              Preview::Recognition::RecognitionStatus::Accepted);
    EXPECT_EQ(Prepare(Preview::Testing::RecognitionWire::MakeVmess(WrongUuid)).Status,
              Preview::Recognition::RecognitionStatus::NoMatch);
    EXPECT_EQ(Prepare(std::move(Tampered)).Status,
              Preview::Recognition::RecognitionStatus::NoMatch);

    for (const auto &Record : Store.Records)
    {
        ASSERT_TRUE(Record);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        EXPECT_EQ(Record->Runtime()->ActiveStreams(), 0U);
    }
}

TEST(CandidateFactory, VlessPrepareOwnsAuthenticatorAcrossConfigLifetime)
{
    const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(41);
    Preview::Account::UuidBytes CredentialBytes{};
    for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
    {
        CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
    }
    auto Owner = Preview::Testing::ProviderAccount(Preview::Account::Credential::Uuid(CredentialBytes), Preview::AccountId{1U}, {})->Authenticator;
    Preview::Vless::ServerConfig Config;
    Config.uuid = Uuid;
    Config.AuthenticatorOwner = Owner;
    auto Binding = Preview::Testing::MakeVlessCandidate(Preview::Composition::Recognition::CandidateOptions{41, "owned-vless", 0, 0, false}, Config);
    Owner.reset();

    auto Storage = std::make_shared<const std::vector<std::byte>>(
        Preview::Testing::RecognitionWire::MakeVless(Uuid));
    Core::PrepareContext Context;
    Context.Candidate = Binding.Spec.Id;
    Context.Snapshot = Core::ProbeSnapshot{Storage};
    const auto Result = RunPrepare(Binding.Spec.Prepare, std::move(Context));

    EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
}

TEST(CandidateFactory, VlessMuxProbeUsesNineteenByteBoundaryAndTypedInspection)
{
    const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(42);
    Preview::Account::UuidBytes AccountUuid{};
    for (std::size_t Index = 0; Index < AccountUuid.size(); ++Index)
    {
        AccountUuid[Index] = static_cast<std::byte>(Uuid[Index]);
    }
    auto Directory = Preview::Testing::ProviderAccount(
        Preview::Account::Credential::Uuid(AccountUuid), Preview::AccountId{7042},
        {.MaxConnections = 1});
    const auto Record = Directory->Store->FindById(Preview::AccountId{7042});
    ASSERT_TRUE(Record);
    auto Authenticator = Directory->Authenticator;

    Preview::Vless::ServerConfig Config;
    Config.uuid = Uuid;
    Config.AuthenticatorOwner = Authenticator;
    auto Binding = Preview::Testing::MakeVlessCandidate(Composition::CandidateOptions{42, "vless-mux", 0, 0, false}, Config);

    Preview::Vless::RequestHeader Request;
    Request.Uuid = Uuid;
    Request.Cmd = Preview::Vless::Command::Mux;
    const auto Wire = Preview::Vless::BuildRequest(Request);
    ASSERT_EQ(Wire.size(), 19U);
    EXPECT_EQ(Binding.Spec.MinimumBytes, 19U);

    auto Storage = std::make_shared<const std::vector<std::byte>>(
        reinterpret_cast<const std::byte *>(Wire.data()),
        reinterpret_cast<const std::byte *>(Wire.data()) + Wire.size());
    const auto Snapshot = Core::ProbeSnapshot{Storage};
    Core::PrepareContext PrepareContext;
    PrepareContext.Candidate = Binding.Spec.Id;
    PrepareContext.Snapshot = Snapshot;
    EXPECT_EQ(Binding.Spec.Inspect(Snapshot), Core::MatchState::Structural);
    const auto Prepared = RunPrepare(Binding.Spec.Prepare, std::move(PrepareContext));
    EXPECT_EQ(Prepared.Status, Core::RecognitionStatus::Accepted);

    Net::io_context Io;
    auto [Client, Server] = Preview::MakeMemoryPair(Io.get_executor());
    auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Server));
    Core::CommitContext CommitContext;
    CommitContext.Candidate = Binding.Spec.Id;
    CommitContext.Inbound = Inbound;
    Core::CommitResult Committed;
    std::exception_ptr Failure;
    Net::co_spawn(Io, Binding.Spec.Commit(std::move(CommitContext)),
        [&Committed, &Failure, &Io](std::exception_ptr Error, Core::CommitResult Result)
        {
            Failure = std::move(Error);
            if (!Failure)
            {
                Committed = std::move(Result);
            }
            Io.stop();
        });
    Io.run();
    ASSERT_FALSE(Failure);
    EXPECT_EQ(Committed.Status, Core::RecognitionStatus::Accepted);
    EXPECT_EQ(Committed.Transport, Inbound);
    Client.Close();
    Inbound->Close();
}

TEST(CandidateFactory, TrojanPrepareOwnsAuthenticatorAcrossConfigLifetime)
{
    auto Owner = Preview::Testing::ProviderAccount(Preview::Account::Credential::Token(Preview::Trojan::Credential("trojan-owned")), Preview::AccountId{1U}, {})->Authenticator;
    Preview::Trojan::ServerConfig Config;
    Config.Password = "unused-static-password";
    Config.AuthenticatorOwner = Owner;
    auto Binding = Preview::Testing::MakeTrojanCandidate(Preview::Composition::Recognition::CandidateOptions{42, "owned-trojan", 0, 0, false}, Config);
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
    auto Owner = Preview::Testing::ProviderAccount(Preview::Account::Credential::Password("connection-secret"), Preview::AccountId{1U}, {})->Authenticator;
    const std::weak_ptr<Preview::Authenticator> WeakOwner = Owner;
    auto Connection = std::make_shared<Preview::Vless::Conn<>>(
        Preview::SharedTransmission{}, Uuid, Owner);

    Owner.reset();
    EXPECT_FALSE(WeakOwner.expired());
    Connection.reset();
    EXPECT_TRUE(WeakOwner.expired());
}

TEST(CandidateFactory, TrojanConnectionRetainsAuthenticatorOwner)
{
    auto Owner = Preview::Testing::ProviderAccount(Preview::Account::Credential::Password("connection-secret"), Preview::AccountId{1U}, {})->Authenticator;
    const std::weak_ptr<Preview::Authenticator> WeakOwner = Owner;
    auto Connection = std::make_shared<Preview::Trojan::Conn<>>(
        Preview::SharedTransmission{}, "password", Owner);

    Owner.reset();
    EXPECT_FALSE(WeakOwner.expired());
    Connection.reset();
    EXPECT_TRUE(WeakOwner.expired());
}

