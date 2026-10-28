#include <TestSupport/Prism/Protocol/Ingress.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
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
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Transport/MemoryStream.hpp>

#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;

    [[nodiscard]] auto MakeHttpCandidate(
        Composition::CandidateOptions Options = {}) -> Composition::CandidateBinding
    {
        auto Factory = std::make_shared<Prism::Http11::Binding>(Prism::Http11::PreparedBinding{
            .Instance = "candidate-factory-test",
            .Executor = Net::system_executor(),
            .RequireAuth = false});
        return Composition::CandidateFactory::MakeHttp(std::move(Options), std::move(Factory));
    }

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
        std::shared_ptr<Prism::Account::AccountStore> Store;
        std::vector<std::shared_ptr<const Prism::Account::AccountBinding>> Records;
    };

    auto AddAccountRecord(
        AccountRecordStore &Store,
        const Prism::AccountId AccountId,
        const std::array<std::uint8_t, 16> &Uuid) -> void
    {
        Prism::Account::UuidBytes CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        std::vector<Prism::Account::CredentialMaterial> Materials;
        const auto Suffix = std::to_string(AccountId.Value());
        Materials.push_back({Prism::Account::CredentialScope{1U}, "account-" + Suffix,
            Prism::Account::Credential::Uuid(CredentialBytes)});
        auto Owned = std::make_shared<const Prism::Account::AccountMaterials>(
            Prism::Account::AccountMaterials::CreateRequest{
                AccountId, "Account " + Suffix, std::move(Materials)});
        auto Prepared = Store.Store->PrepareUpsert(Prism::Account::AccountDefinition{
            std::move(Owned), {.Quota = {.MaxConnections = 1}}});
        EXPECT_TRUE(Prepared);
        if (!Prepared)
        {
            return;
        }
        EXPECT_TRUE(Store.Store->Commit(*Prepared));
        Store.Records.push_back(Store.Store->FindById(AccountId));
    }

    auto MakeProtocolIngressAccounts(AccountRecordStore &Store)
        -> std::shared_ptr<Prism::Testing::ProtocolIngressAccounts>
    {
        auto Accounts = std::make_shared<Prism::Testing::ProtocolIngressAccounts>();
        Accounts->Store = Store.Store;
        Accounts->Generation = Prism::Testing::ProviderPin();
        Accounts->GenerationUseState = Prism::Testing::MakeProtocolIngressUseState();
        Accounts->Publication = std::make_shared<Prism::Runtime::GenerationPublication>();

        auto View = Store.Store->CompileScope(Prism::Account::CredentialScope{1U});
        if (!View) throw std::runtime_error("VMess fixture credential scope failed");
        Accounts->Credentials = std::move(*View);

        auto Prepared = Accounts->Publication->Prepare(
            {}, Accounts->Generation, Store.Store->AccountIds());
        if (!Prepared) throw std::runtime_error("VMess fixture publication prepare failed");
        if (!Accounts->Publication->Publish(*Prepared))
        {
            throw std::runtime_error("VMess fixture publication failed");
        }
        const auto Attached = Store.Store->RuntimeRegistry()->AttachAdmissionAuthority(
            Accounts->Publication);
        if (!Attached) throw std::runtime_error("VMess fixture authority attachment failed");

        Accounts->Authenticator = std::make_shared<Prism::Testing::ProviderAuthenticator>(
            Store.Store, Accounts->Credentials, Accounts->Publication);
        return Accounts;
    }

} // namespace

TEST(CandidateFactory, CreatesSocks5Binding)
{
    Prism::Socks5::ServerConfig Config;
    const auto Binding = Composition::CandidateFactory::MakeSocks5(
        Composition::CandidateOptions{7, "edge-socks", 2, 1}, Prism::Testing::MakeSocks5Binding(Config));

    EXPECT_EQ(Binding.Spec.Id, 7);
    EXPECT_EQ(Binding.Spec.Name, "edge-socks");
    EXPECT_EQ(Binding.Spec.Protocol, Prism::Contract::ProtocolType::Socks5);
    EXPECT_TRUE(Binding.Accept);
    EXPECT_TRUE(Binding.Spec.Inspect);
    EXPECT_TRUE(Binding.Spec.Commit);
}

TEST(CandidateFactory, RejectsBindingWithoutResolver)
{
    auto Binding = MakeHttpCandidate(Prism::Composition::Recognition::CandidateOptions{8});
    Binding.Accept = {};

    auto Built = Composition::ProfileBuilder::Build(std::move(Binding));

    EXPECT_FALSE(Built.has_value());
}

TEST(CandidateFactory, ClassifiesUnbracketedIpv6HttpAuthorityAsHttpStructure)
{
    const auto Binding = MakeHttpCandidate();
    const std::string Request = "CONNECT 2001:db8::1:443 HTTP/1.1\r\n"
                                "Host: 2001:db8::1:443\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    const auto State = Binding.Spec.Inspect(Prism::Recognition::ProbeSnapshot{Storage});

    EXPECT_EQ(State, Prism::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, ClassifiesNonIpv6BracketedHttpAuthorityAsHttpStructure)
{
    const auto Binding = MakeHttpCandidate();
    const std::string Request = "CONNECT [not-an-ip]:443 HTTP/1.1\r\n"
                                "Host: [not-an-ip]:443\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    const auto State = Binding.Spec.Inspect(Prism::Recognition::ProbeSnapshot{Storage});

    EXPECT_EQ(State, Prism::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, AcceptsValidBracketedIpv6HttpAuthority)
{
    const auto Binding = MakeHttpCandidate();
    const std::string Request = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"
                                "Host: [2001:db8::1]:443\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    const auto State = Binding.Spec.Inspect(Prism::Recognition::ProbeSnapshot{Storage});

    EXPECT_EQ(State, Prism::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, RecognizesAbsoluteFormHttpProxyRequests)
{
    const auto Binding = MakeHttpCandidate();
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

    EXPECT_EQ(Binding.Spec.Inspect(Prism::Recognition::ProbeSnapshot{Storage}),
              Prism::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, ClassifiesUnsupportedHttpsAbsoluteFormAsHttpStructure)
{
    const auto Binding = MakeHttpCandidate();
    const std::string Request = "GET https://example.com/private HTTP/1.1\r\n"
                                "Host: example.com\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    EXPECT_EQ(Binding.Spec.Inspect(Prism::Recognition::ProbeSnapshot{Storage}),
              Prism::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, ClassifiesLiteralFragmentTargetAsHttpStructure)
{
    const auto Binding = MakeHttpCandidate();
    const std::string Request = "GET /private#fragment HTTP/1.1\r\n"
                                "Host: example.com\r\n\r\n";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Request.size());
    for (const auto Character : Request)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    EXPECT_EQ(Binding.Spec.Inspect(Prism::Recognition::ProbeSnapshot{Storage}),
              Prism::Recognition::MatchState::Structural);
}

TEST(CandidateFactory, DoesNotRecognizeHttpResponseAsInboundProxyRequest)
{
    const auto Binding = MakeHttpCandidate();
    const std::string Response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Response.size());
    for (const auto Character : Response)
    {
        Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
    }

    EXPECT_EQ(Binding.Spec.Inspect(Prism::Recognition::ProbeSnapshot{Storage}),
              Prism::Recognition::MatchState::Rejected);
}

TEST(CandidateFactory, RejectsAuthenticatedVmessUnknownCommand)
{
    constexpr std::array<std::uint8_t, 16> Uuid{
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};
    Prism::Vmess::Message Message;
    Message.Cmd = 0x99;
    Message.dst.Type = Prism::Vmess::AddressType::Domain;
    Message.dst.Host = "example.com";
    Message.dst.Port = 443;
    Message.RequestNonce.fill(0x11);
    Message.RequestKey.fill(0x22);
    Message.RespHeader = 0x42;
    Prism::Vmess::Serializer Serializer(Uuid);
    Serializer.Reset(Message, static_cast<std::uint64_t>(
                                  std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count()));
    std::array<std::uint8_t, 1024> Wire{};
    std::error_code SerializeError;
    const auto Size = Serializer.Get(boost::asio::mutable_buffer(Wire.data(), Wire.size()), SerializeError);
    ASSERT_FALSE(SerializeError);

    auto Binding = Prism::Testing::MakeVmessCandidate(Prism::Composition::Recognition::CandidateOptions{7, "vmess", 0, 0, false}, Prism::Vmess::ServerConfig{Uuid});
    auto Storage = std::make_shared<std::vector<std::byte>>();
    Storage->reserve(Size);
    for (std::size_t Index = 0; Index < Size; ++Index)
    {
        Storage->push_back(static_cast<std::byte>(Wire[Index]));
    }

    Prism::Recognition::PrepareResult Result;
    boost::asio::io_context Io;
    Prism::Recognition::PrepareContext Context;
    Context.Candidate = 7;
    Context.Snapshot = Prism::Recognition::ProbeSnapshot{Storage};
    boost::asio::co_spawn(
        Io, Binding.Spec.Prepare(std::move(Context)),
        [&Io, &Result](std::exception_ptr Error, Prism::Recognition::PrepareResult Value)
        {
            if (!Error)
            {
                Result = std::move(Value);
            }
            Io.stop();
        });
    Io.run();

    EXPECT_EQ(Result.Status, Prism::Recognition::RecognitionStatus::NoMatch);
}

TEST(CandidateFactory, VmessPrepareAcceptsAnyConfiguredDirectoryUuid)
{
    const auto FirstUuid = Prism::Testing::RecognitionWire::MakeUuid(61);
    const auto SecondUuid = Prism::Testing::RecognitionWire::MakeUuid(62);
    const auto WrongUuid = Prism::Testing::RecognitionWire::MakeUuid(63);
    AccountRecordStore Store{std::make_shared<Prism::Account::AccountStore>(), {}};
    AddAccountRecord(Store, Prism::AccountId{7061}, FirstUuid);
    AddAccountRecord(Store, Prism::AccountId{7062}, SecondUuid);

    Prism::Vmess::ServerConfig Configuration;
    Configuration.uuid = FirstUuid;
    auto Accounts = MakeProtocolIngressAccounts(Store);
    Prism::Testing::VmessIngressResources Resources;
    Resources.UseState = Accounts->GenerationUseState;
    Resources.Executor = Net::system_executor();
    Resources.Accounts = std::move(Accounts);
    auto Owner = Prism::Testing::MakeVmessProviderBinding(
        std::move(Configuration), std::move(Resources));
    auto Candidate = Prism::Composition::Recognition::CandidateFactory::MakeVmess(
        Prism::Composition::Recognition::CandidateOptions{61, "vmess-directory", 0, 0, false},
        std::move(Owner), std::nullopt);
    ASSERT_TRUE(Candidate);
    auto Binding = std::move(*Candidate);

    const auto Prepare = [&Binding](std::vector<std::byte> Wire)
    {
        auto Storage = std::make_shared<const std::vector<std::byte>>(std::move(Wire));
        Prism::Recognition::PrepareContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Snapshot = Prism::Recognition::ProbeSnapshot{Storage};
        return RunPrepare(Binding.Spec.Prepare, std::move(Context));
    };

    auto Tampered = Prism::Testing::RecognitionWire::MakeVmess(SecondUuid);
    ASSERT_FALSE(Tampered.empty());
    Tampered.front() ^= std::byte{0x80};

    EXPECT_EQ(Prepare(Prism::Testing::RecognitionWire::MakeVmess(FirstUuid)).Status,
              Prism::Recognition::RecognitionStatus::Accepted);
    EXPECT_EQ(Prepare(Prism::Testing::RecognitionWire::MakeVmess(SecondUuid)).Status,
              Prism::Recognition::RecognitionStatus::Accepted);
    EXPECT_EQ(Prepare(Prism::Testing::RecognitionWire::MakeVmess(WrongUuid)).Status,
              Prism::Recognition::RecognitionStatus::NoMatch);
    EXPECT_EQ(Prepare(std::move(Tampered)).Status,
              Prism::Recognition::RecognitionStatus::NoMatch);

    for (const auto &Record : Store.Records)
    {
        ASSERT_TRUE(Record);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        EXPECT_EQ(Record->Runtime()->ActiveStreams(), 0U);
    }
}

TEST(CandidateFactory, VlessPrepareOwnsAuthenticatorAcrossConfigLifetime)
{
    const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(41);
    Prism::Account::UuidBytes CredentialBytes{};
    for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
    {
        CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
    }
    auto Owner = Prism::Testing::ProviderAccount(Prism::Account::Credential::Uuid(CredentialBytes), Prism::AccountId{1U}, {})->Authenticator;
    Prism::Vless::ServerConfig Config;
    Config.uuid = Uuid;
    Config.AuthenticatorOwner = Owner;
    auto Binding = Prism::Testing::MakeVlessCandidate(Prism::Composition::Recognition::CandidateOptions{41, "owned-vless", 0, 0, false}, Config);
    Owner.reset();

    auto Storage = std::make_shared<const std::vector<std::byte>>(
        Prism::Testing::RecognitionWire::MakeVless(Uuid));
    Core::PrepareContext Context;
    Context.Candidate = Binding.Spec.Id;
    Context.Snapshot = Core::ProbeSnapshot{Storage};
    const auto Result = RunPrepare(Binding.Spec.Prepare, std::move(Context));

    EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
}

TEST(CandidateFactory, VlessMuxProbeUsesNineteenByteBoundaryAndTypedInspection)
{
    const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(42);
    Prism::Account::UuidBytes AccountUuid{};
    for (std::size_t Index = 0; Index < AccountUuid.size(); ++Index)
    {
        AccountUuid[Index] = static_cast<std::byte>(Uuid[Index]);
    }
    auto Directory = Prism::Testing::ProviderAccount(
        Prism::Account::Credential::Uuid(AccountUuid), Prism::AccountId{7042},
        {.MaxConnections = 1});
    const auto Record = Directory->Store->FindById(Prism::AccountId{7042});
    ASSERT_TRUE(Record);
    auto Authenticator = Directory->Authenticator;

    Prism::Vless::ServerConfig Config;
    Config.uuid = Uuid;
    Config.AuthenticatorOwner = Authenticator;
    auto Binding = Prism::Testing::MakeVlessCandidate(Composition::CandidateOptions{42, "vless-mux", 0, 0, false}, Config);

    Prism::Vless::RequestHeader Request;
    Request.Uuid = Uuid;
    Request.Cmd = Prism::Vless::Command::Mux;
    const auto Wire = Prism::Vless::BuildRequest(Request);
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
    auto [Client, Server] = Prism::MakeMemoryPair(Io.get_executor());
    auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(Server));
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
    auto Owner = Prism::Testing::ProviderAccount(Prism::Account::Credential::Token(Prism::Trojan::Credential("trojan-owned")), Prism::AccountId{1U}, {})->Authenticator;
    Prism::Trojan::ServerConfig Config;
    Config.Password = "unused-static-password";
    Config.AuthenticatorOwner = Owner;
    auto Binding = Prism::Testing::MakeTrojanCandidate(Prism::Composition::Recognition::CandidateOptions{42, "owned-trojan", 0, 0, false}, Config);
    Owner.reset();

    auto Storage = std::make_shared<const std::vector<std::byte>>(
        Prism::Testing::RecognitionWire::MakeTrojan("trojan-owned"));
    Core::PrepareContext Context;
    Context.Candidate = Binding.Spec.Id;
    Context.Snapshot = Core::ProbeSnapshot{Storage};
    const auto Result = RunPrepare(Binding.Spec.Prepare, std::move(Context));

    EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
}

TEST(CandidateFactory, VlessConnectionRetainsAuthenticatorOwner)
{
    const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(43);
    auto Owner = Prism::Testing::ProviderAccount(Prism::Account::Credential::Password("connection-secret"), Prism::AccountId{1U}, {})->Authenticator;
    const std::weak_ptr<Prism::Authenticator> WeakOwner = Owner;
    auto Upstream = std::make_shared<Prism::MemoryStream>(Net::system_executor());
    auto Connection = std::make_shared<Prism::Vless::Conn<>>(
        Upstream, Uuid, Owner);

    Owner.reset();
    EXPECT_FALSE(WeakOwner.expired());
    Connection.reset();
    EXPECT_TRUE(WeakOwner.expired());
    (void)Upstream->Close();
}

TEST(CandidateFactory, TrojanConnectionRetainsAuthenticatorOwner)
{
    auto Owner = Prism::Testing::ProviderAccount(Prism::Account::Credential::Password("connection-secret"), Prism::AccountId{1U}, {})->Authenticator;
    const std::weak_ptr<Prism::Authenticator> WeakOwner = Owner;
    auto Upstream = std::make_shared<Prism::MemoryStream>(Net::system_executor());
    auto Connection = std::make_shared<Prism::Trojan::Conn<>>(
        Upstream, "password", Owner);

    Owner.reset();
    EXPECT_FALSE(WeakOwner.expired());
    Connection.reset();
    EXPECT_TRUE(WeakOwner.expired());
    (void)Upstream->Close();
}
