/** @file ProviderAcceptPathTest.cpp @brief 原 ConfigurationGeneration 的真实工厂 bytes/租约/pin/关闭。 */
#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <system_error>
#include <TestSupport/Fixtures/RecognitionWire.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/AccountAdmissionAuthority.hpp>
namespace
{
    namespace Net = boost::asio;
    namespace P = Prism::Composition::Provider;
    /** @brief 构造携带显式有界字节池的 provider 接入输入。 */
    [[nodiscard]] auto MakeStreamAcceptInput(Prism::SharedTransmission Inbound,
        Prism::Contract::RequestMetadata Metadata={}) -> Prism::Contract::StreamAcceptInput
    {
        return {std::move(Inbound),std::move(Metadata),
            std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount=8})};
    }
    auto Generation() -> Prism::Application::Configuration::SharedConfigurationGeneration
    {
        auto Root = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        auto Result = Prism::Application::Startup::GenerationPhase::BuildGeneration(
            {Root / "Prism/Application/Configuration/PrismConfiguration.json", {}});
        if (!Result)
            throw std::runtime_error(Result.error().Message);
        return *Result;
    }

    /** @brief 持有一次 SOCKS5 工厂接入的双方传输、配置 pin 和回显结果。 */
    struct PreparedSocksEcho final
    {
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::shared_ptr<Prism::MemoryStream> Client, Server;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> Generation;
        const std::string Payload{"prepared-socks-generation-payload"};
        bool Accepted{false}, Bytes{false}, Lease{false}, Drained{false};

        /** @brief 服务端取得唯一租约，回显完整 payload 后关闭已接入传输。 */
        auto Accept() -> Net::awaitable<void>
        {
            auto Result = co_await Factory->Accept(MakeStreamAcceptInput(Server));
            EXPECT_TRUE(Result);
            if (!Result) co_return;
            Accepted = true;
            Lease = bool(Result->AccountLease);
            EXPECT_EQ(Result->AccountId, Prism::AccountId{1});
            EXPECT_FALSE(Generation.expired());
            EXPECT_EQ(co_await Result->PostDial(Prism::Fault::Code::Success),
                Prism::Fault::Code::Success);
            std::vector<std::byte> Buffer(Payload.size());
            const auto Read = co_await Result->Transport()->ReadSome(Buffer);
            EXPECT_TRUE(Read.Failure.Succeeded());
            EXPECT_EQ(Read.Bytes, Payload.size());
            EXPECT_LE(Read.Bytes, Buffer.size());
            const auto ReadBytes = (std::min)(Read.Bytes, Buffer.size());
            const auto Write = co_await Result->Transport()->WriteSome(
                std::span<const std::byte>(Buffer.data(), ReadBytes));
            EXPECT_TRUE(Write.Failure.Succeeded());
            EXPECT_EQ(Write.Bytes, ReadBytes);
            Result->Transport()->Close();
        }

        /** @brief 客户端完成原用户名认证，并核对完整回显。 */
        auto Request() -> Net::awaitable<void>
        {
            Prism::Socks5::ClientConfig Config{true, "user", "local-token"};
            auto [Error, Connection] = co_await Prism::Socks5::Connect(Client, Config,
                {Prism::Socks5::AddressType::Domain, "echo", 7});
            EXPECT_EQ(Error, Prism::Error::None);
            if (!Connection) co_return;
            const auto Write = co_await Connection->WriteSome(std::as_bytes(std::span(Payload)));
            EXPECT_TRUE(Write.Failure.Succeeded());
            EXPECT_EQ(Write.Bytes, Payload.size());
            std::vector<std::byte> Reply(Payload.size());
            const auto Read = co_await Connection->ReadSome(Reply);
            EXPECT_TRUE(Read.Failure.Succeeded());
            EXPECT_EQ(Read.Bytes, Payload.size());
            Bytes = Read.Failure.Succeeded() && Read.Bytes == Payload.size() &&
                std::memcmp(Reply.data(), Payload.data(), Read.Bytes) == 0;
            Connection->Close();
        }

        /** @brief 等待双方实际完成后排空 binding；异常同样先关闭和排空。 */
        auto Run(P::BoundCatalog &Bound) -> Net::awaitable<void>
        {
            std::exception_ptr Failure;
            try
            {
                using Net::experimental::awaitable_operators::operator&&;
                co_await (Accept() && Request());
            }
            catch (...) { Failure = std::current_exception(); }
            Client->Close();
            Server->Close();
            Bound.Close();
            const auto DrainResult = co_await Bound.Drain();
            Drained = static_cast<bool>(DrainResult);
            EXPECT_TRUE(DrainResult);
            if (Failure) std::rethrow_exception(Failure);
        }
    };

    /** @brief 拥有被丢弃数据面的入站与对端，验证最终关闭和工厂排空。 */
    struct DroppedPlaneProbe final
    {
        std::shared_ptr<Prism::Socks5::Binding> Owner;
        std::shared_ptr<Prism::MemoryStream> Client, Server;

        auto Run() -> Net::awaitable<void>
        {
            const std::array<std::uint8_t, 13> Wire{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 7};
            const auto Write = co_await Client->WriteSome(std::as_bytes(std::span(Wire)));
            EXPECT_TRUE(Write.Failure.Succeeded());
            EXPECT_EQ(Write.Bytes, Wire.size());
            {
                auto Result = co_await Owner->Accept(MakeStreamAcceptInput(Server));
                EXPECT_TRUE(Result);
            }
            co_await Net::post(co_await Net::this_coro::executor, Net::use_awaitable);
            EXPECT_FALSE(Server->IsOpen());
            Owner->Close();
            const auto DrainResult = co_await Owner->Drain();
            EXPECT_TRUE(DrainResult);
            Client->Close();
            Server->Close();
        }
    };

    /** @brief 持有第二账户 SS2022 接入所需的 wire、端点、认证目录和结果。 */
    struct SecondAccountEcho final
    {
        std::shared_ptr<Prism::Shadowsocks2022::Binding> Binding;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::shared_ptr<Prism::MemoryStream> Client, Server;
        std::shared_ptr<Prism::Account::AccountStore> Accounts;
        std::shared_ptr<const std::vector<std::byte>> Storage;
        std::array<std::uint8_t, 16> Key;
        const std::string Payload{"second-account-prepared-stream"};
        bool Echo{false};
        bool DrainSucceeded{false};

        auto Accept() -> Net::awaitable<void>
        {
            auto Result = co_await Factory->Accept(MakeStreamAcceptInput(Server));
            EXPECT_TRUE(Result);
            if (!Result) co_return;
            EXPECT_EQ(Result->AccountId, Prism::AccountId{2});
            EXPECT_TRUE(Result->AccountLease);
            EXPECT_EQ(Result->AccountLease.Binding()->Runtime()->ActiveConnections(), 1);
            std::vector<std::byte> Buffer(Payload.size());
            const auto Read = co_await Result->Transport()->ReadSome(Buffer);
            EXPECT_TRUE(Read.Failure.Succeeded());
            EXPECT_EQ(Read.Bytes, Payload.size());
            EXPECT_LE(Read.Bytes, Buffer.size());
            const auto ReadBytes = (std::min)(Read.Bytes, Buffer.size());
            const auto Write = co_await Result->Transport()->WriteSome(
                std::span<const std::byte>(Buffer.data(), ReadBytes));
            EXPECT_TRUE(Write.Failure.Succeeded());
            EXPECT_EQ(Write.Bytes, ReadBytes);
            Result->Transport()->Close();
        }

        auto Request() -> Net::awaitable<void>
        {
            Prism::Shadowsocks2022::ClientConfig Config;
            Config.Psk = Key;
            auto [ErrorValue, Connection] = co_await Prism::Shadowsocks2022::Connect(Client, Config,
                {Prism::Shadowsocks2022::AddressType::Domain, "echo", 7});
            EXPECT_EQ(ErrorValue, Prism::Error::None);
            if (!Connection) co_return;
            const auto Write = co_await Connection->WriteSome(std::as_bytes(std::span(Payload)));
            EXPECT_TRUE(Write.Failure.Succeeded());
            EXPECT_EQ(Write.Bytes, Payload.size());
            std::vector<std::byte> Response(Payload.size());
            const auto Read = co_await Connection->ReadSome(Response);
            EXPECT_TRUE(Read.Failure.Succeeded());
            EXPECT_EQ(Read.Bytes, Payload.size());
            Echo = Read.Failure.Succeeded() && Read.Bytes == Payload.size() &&
                std::memcmp(Response.data(), Payload.data(), Read.Bytes) == 0;
            Connection->Close();
        }

        /** @brief Prepare 不取得租约；放开占用后 winner 接入，再核对目录归零。 */
        auto Run(const Prism::Recognition::CandidateSpec &Spec,
            Prism::Account::AccountLease &Held) -> Net::awaitable<void>
        {
            std::exception_ptr Failure;
            try
            {
                Prism::Recognition::PrepareContext Context;
                Context.Candidate = 7;
                Context.Snapshot = Prism::Recognition::ProbeSnapshot{Storage};
                auto Result = co_await Spec.Prepare(std::move(Context));
                EXPECT_EQ(Result.Status, Prism::Recognition::RecognitionStatus::Accepted);
                EXPECT_EQ(Held.Binding()->Runtime()->ActiveConnections(), 1);
                Held.Release();
                using Net::experimental::awaitable_operators::operator&&;
                co_await (Accept() && Request());
            }
            catch (...) { Failure = std::current_exception(); }
            if (Held) Held.Release();
            Client->Close();
            Server->Close();
            Binding->Close();
            try
            {
                const auto DrainResult = co_await Binding->Drain();
                DrainSucceeded = static_cast<bool>(DrainResult);
                EXPECT_TRUE(DrainResult);
            }
            catch (...) { if (!Failure) Failure = std::current_exception(); }
            Accounts->ForEach([](const auto &Record)
                { EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0); });
            if (Failure) std::rethrow_exception(Failure);
        }
    };

    struct SsResponseWriteFailureCase final
    {
        std::shared_ptr<Prism::Shadowsocks2022::Binding> Binding;
        std::shared_ptr<Prism::PrismMockTransport> Raw;
        std::size_t WireSize;
        std::shared_ptr<Prism::Account::AccountStore> Accounts;
    };

    auto RunSsResponseWriteFailure(SsResponseWriteFailureCase Case) -> Net::awaitable<void>
    {
        {
            auto Outcome = co_await Case.Binding->Accept(MakeStreamAcceptInput(Case.Raw));
            EXPECT_FALSE(Outcome);
            if (Outcome)
                (void)Outcome->Transport()->Close();
            else
            {
                EXPECT_EQ(Outcome.error().Code, Prism::Fault::Code::IoError);
                EXPECT_FALSE(Outcome.error().Native);
            }
            EXPECT_EQ(Case.Raw->Written.size(), 1U);
            EXPECT_EQ(Case.Raw->ReadsDone, Case.WireSize - 15U);
        }
        Case.Binding->Close();
        const auto Drain = co_await Case.Binding->Drain();
        EXPECT_TRUE(Drain);
        EXPECT_FALSE(Case.Raw->IsOpen());
        Case.Accounts->ForEach([](const auto& Record)
        { EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U); });
    }

    /** @brief 拥有两次工厂接入的双方端点，验证数据面移动时的唯一关闭者。 */
    struct MovedPlaneProbe final
    {
        std::shared_ptr<Prism::Socks5::Binding> Owner;
        std::array<std::shared_ptr<Prism::MemoryStream>, 2> Clients, Servers;

        auto Run() -> Net::awaitable<void>
        {
            const std::array<std::uint8_t, 13> Wire{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 7};
            const auto FirstWrite = co_await Clients[0]->WriteSome(std::as_bytes(std::span(Wire)));
            const auto SecondWrite = co_await Clients[1]->WriteSome(std::as_bytes(std::span(Wire)));
            EXPECT_TRUE(FirstWrite.Failure.Succeeded());
            EXPECT_EQ(FirstWrite.Bytes, Wire.size());
            EXPECT_TRUE(SecondWrite.Failure.Succeeded());
            EXPECT_EQ(SecondWrite.Bytes, Wire.size());
            auto First = co_await Owner->Accept(MakeStreamAcceptInput(Servers[0]));
            auto Second = co_await Owner->Accept(MakeStreamAcceptInput(Servers[1]));
            EXPECT_TRUE(First);
            EXPECT_TRUE(Second);
            if (!First || !Second) co_return;
            Prism::Contract::ProtocolDataPlane Destination = std::move(*First);
            EXPECT_FALSE(First->HasTransport());
            Destination = std::move(*Second);
            EXPECT_FALSE(Second->HasTransport());
            co_await Net::post(co_await Net::this_coro::executor, Net::use_awaitable);
            EXPECT_FALSE(Servers[0]->IsOpen());
            EXPECT_TRUE(Servers[1]->IsOpen());
            Destination = Prism::Contract::ProtocolDataPlane{};
            co_await Net::post(co_await Net::this_coro::executor, Net::use_awaitable);
            EXPECT_FALSE(Servers[1]->IsOpen());
            Owner->Close();
            const auto DrainResult = co_await Owner->Drain();
            EXPECT_TRUE(DrainResult);
            Clients[0]->Close();
            Clients[1]->Close();
        }
    };

    /** @brief 用真实配置pin编译协议账户服务；失败不伪造空目录。 */
    auto MakeAccountCatalog(Prism::Application::Configuration::SharedConfigurationGeneration Pin)
        -> std::expected<std::shared_ptr<Prism::Application::AccountCatalog>,
            Prism::Application::StartupError>
    {
        auto Store = std::make_shared<Prism::Account::AccountStore>();
        auto Identities = std::make_shared<Prism::Application::AccountIdentityRegistry>();
        auto Prepared = Prism::Application::Assembly::PrepareAccountCatalog({Pin, Store, Identities});
        if (!Prepared)
        {
            return std::unexpected(Prepared.error());
        }
        const auto Published = Store->Commit(Prepared->Update);
        if (!Published)
        {
            return std::unexpected(Prism::Application::StartupError{});
        }
        const auto Authority = Prism::Testing::AttachAccountAdmissionAuthority(
            Identities->RuntimeRegistry());
        if (!Authority)
        {
            return std::unexpected(Prism::Application::StartupError{});
        }
        return std::make_shared<Prism::Application::AccountCatalog>(std::move(Prepared->Catalog));
    }

    /** @brief 取该pin第一个协议实例的正式认证服务；空表示配置没有对应域。 */
    auto ProtocolServices(const Prism::Application::AccountCatalog &Catalog,
        const Prism::Application::Configuration::SharedConfigurationGeneration &Pin)
        -> const Prism::Contract::AuthenticationServices *
    {
        return Catalog.Find(Pin->Configuration().Protocols.front().Id);
    }

    /** @brief 在同一 executor 上构造拥有配置 pin 的冷路径 catalog。 */
    struct PinnedCatalogBuilder final
    {
        Net::any_io_executor Executor;

        auto Build(Prism::Application::Configuration::SharedConfigurationGeneration Pin,
            std::string Id,
            const Prism::Application::AccountCatalog &Catalog) -> P::BoundCatalog
        {
            auto Config = Pin->Configuration().Protocols.front();
            Config.Id = std::move(Id);
            Prism::Contract::AuthenticationServices Services;
            if (const auto *Found = ProtocolServices(Catalog, Pin))
            {
                Services = *Found;
            }
            auto Prepared = P::ProviderCatalog::Prepare(
                {Pin, {{Config, true, false, std::move(Services)}}},
                {Executor, {}, {}, {}});
            auto Frozen = Prepared->Freeze();
            return std::move(*Frozen->Bind({}));
        }
    };

    /** @brief 借用 TEST 作用域的两个 catalog，并持有移动期间实际使用的端点和别名。 */
    struct MovedCatalogProbe final
    {
        P::BoundCatalog &Destination, &Incoming;
        std::shared_ptr<Prism::Socks5::Binding> OldOwner;
        std::shared_ptr<Prism::Contract::StreamFactory> OldAlias, NewAlias;
        std::array<std::shared_ptr<Prism::MemoryStream>, 2> Clients;
        std::array<std::shared_ptr<Prism::MemoryStream>, 3> Servers;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> OldWeak, NewWeak;
        bool Completed{false};

        auto Run() -> Net::awaitable<void>
        {
            const std::array<std::uint8_t, 31> Wire{5, 1, 2, 1, 4, 'u', 's', 'e', 'r', 11, 'l', 'o', 'c', 'a',
                'l', '-', 't', 'o', 'k', 'e', 'n', 5, 1, 0, 1, 127, 0, 0, 1, 0, 7};
            const auto FirstWrite = co_await Clients[0]->WriteSome(std::as_bytes(std::span(Wire)));
            EXPECT_TRUE(FirstWrite.Failure.Succeeded());
            EXPECT_EQ(FirstWrite.Bytes, Wire.size());
            auto OldPlane = co_await OldAlias->Accept(MakeStreamAcceptInput(Servers[0]));
            EXPECT_TRUE(OldPlane);
            if (!OldPlane) co_return;
            auto Record = OldPlane->AccountLease.Binding();
            EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1);
            Destination = std::move(Incoming);
            Incoming.Close();
            co_await Net::post(co_await Net::this_coro::executor, Net::use_awaitable);
            EXPECT_FALSE(Servers[0]->IsOpen());
            EXPECT_FALSE(OldWeak.expired());
            auto Refused = co_await OldAlias->Accept(MakeStreamAcceptInput(Servers[2]));
            EXPECT_FALSE(Refused);
            const auto SecondWrite = co_await Clients[1]->WriteSome(std::as_bytes(std::span(Wire)));
            EXPECT_TRUE(SecondWrite.Failure.Succeeded());
            EXPECT_EQ(SecondWrite.Bytes, Wire.size());
            auto NewPlane = co_await NewAlias->Accept(MakeStreamAcceptInput(Servers[1]));
            EXPECT_TRUE(NewPlane);
            EXPECT_TRUE(Servers[1]->IsOpen());
            EXPECT_NE(Destination.Find("new"), nullptr);
            OldPlane = std::unexpected(Prism::Error::NotOpen);
            const auto OldDrain = co_await OldOwner->Drain();
            EXPECT_TRUE(OldDrain);
            EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0);
            EXPECT_TRUE(OldWeak.expired());
            NewPlane = std::unexpected(Prism::Error::NotOpen);
            Destination.Close();
            const auto DestinationDrain = co_await Destination.Drain();
            EXPECT_TRUE(DestinationDrain);
            EXPECT_TRUE(NewWeak.expired());
            Clients[0]->Close();
            Clients[1]->Close();
            Completed = true;
        }
    };
    TEST(ProviderAcceptPath, SelectsBoundProviderWithoutStringLookup)
    {
        Net::io_context Io;
        auto Pin = Generation();
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> Weak = Pin;
        auto CatalogResult = MakeAccountCatalog(*Pin);
        ASSERT_TRUE(CatalogResult);
        auto Directory = *CatalogResult;
        const auto *Services = ProtocolServices(*Directory, Pin);
        ASSERT_TRUE(Services);
        auto Prepared = P::ProviderCatalog::Prepare(
            {Pin, {{Pin->Configuration().Protocols.front(), true, false, *Services}}},
            {Io.get_executor(), {}, {}, {}});
        ASSERT_TRUE(Prepared);
        auto Frozen = Prepared->Freeze();
        ASSERT_TRUE(Frozen);
        auto Bound = Frozen->Bind({});
        ASSERT_TRUE(Bound);
        auto Factory = Bound->Find("protocol-socks5")->Stream();
        auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
        auto Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
        Pin.reset();
        Directory.reset();
        EXPECT_FALSE(Weak.expired());
        PreparedSocksEcho Probe{Factory, Client, Server, Weak};
        Net::co_spawn(Io, Probe.Run(*Bound), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
        Io.run();
        EXPECT_TRUE(Probe.Accepted);
        EXPECT_TRUE(Probe.Bytes);
        EXPECT_TRUE(Probe.Lease);
        EXPECT_TRUE(Probe.Drained);
        EXPECT_TRUE(Weak.expired());
    }
    TEST(ProviderAcceptPath, RejectsProviderProtocolWhenTypedBindingIsAbsent)
    {
        const P::BoundCatalog Empty;
        EXPECT_EQ(Empty.Find("protocol-socks5"), nullptr);
    }
    TEST(ProviderAcceptPath, StandardBindCreatesTypedOwnerAndClosesItExactlyOnce)
    {
        Net::io_context Io;
        auto Pin = Generation();
        auto CatalogResult = MakeAccountCatalog(*Pin);
        ASSERT_TRUE(CatalogResult);
        auto Directory = *CatalogResult;
        const auto *Services = ProtocolServices(*Directory, Pin);
        ASSERT_TRUE(Services);
        auto Prepared = P::ProviderCatalog::Prepare(
            {Pin, {{Pin->Configuration().Protocols.front(), true, false, *Services}}},
            {Io.get_executor(), {}, {}, {}});
        ASSERT_TRUE(Prepared);
        auto Frozen = Prepared->Freeze();
        ASSERT_TRUE(Frozen);
        auto Bound = Frozen->Bind({});
        ASSERT_TRUE(Bound);
        auto Factory = Bound->Find("protocol-socks5")->Stream();
        Bound->Close();
        Bound->Close();
        bool Refused = false;
        auto [Client, Server] = Prism::MakeMemoryPair(Io.get_executor());
        auto Run = [&]() -> Net::awaitable<void>
        {
            auto Result =
                co_await Factory->Accept(MakeStreamAcceptInput(
                    std::make_shared<Prism::MemoryStream>(std::move(Server))));
            Refused = !Result;
            const auto DrainResult = co_await Bound->Drain();
            EXPECT_TRUE(DrainResult);
        };
        Net::co_spawn(Io, Run(), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
        Io.run();
        EXPECT_TRUE(Refused);
    }
    TEST(ProviderAcceptPath, DroppingAcceptedPlaneClosesActualInboundBeforeDrain)
    {
        Net::io_context Io;
        Prism::Socks5::ServerConfig Config;
        Config.EnableUdp = false;
        auto Owner = Prism::Testing::MakeSocks5Binding(Config);
        auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
        auto Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
        DroppedPlaneProbe Probe{Owner, Client, Server};
        Net::co_spawn(Io, Probe.Run(), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
        Io.run();
    }
    TEST(ProviderAcceptPath, SsSecondAccountProbeTakesNoLeaseAndWinnerMovesExactlyOne)
    {
        Net::io_context Io;
        auto Pin = Generation();
        auto Accounts = std::make_shared<Prism::Account::AccountStore>();
        const auto Key = Prism::Testing::RecognitionWire::MakePsk(0x77);
        const auto First = Prism::Testing::RecognitionWire::MakePsk(0x31);
        for (const auto& [Id, Bytes] : std::array{std::pair{1, First}, std::pair{2, Key}})
        {
            std::vector<Prism::Account::CredentialMaterial> Materials;
            Materials.push_back({Prism::Account::CredentialScope{1U}, {},
                Prism::Account::Credential::Psk(
                    std::string_view(reinterpret_cast<const char*>(Bytes.data()), Bytes.size()))});
            auto Owned = std::make_shared<const Prism::Account::AccountMaterials>(
                Prism::Account::AccountMaterials::CreateRequest{
                    Prism::AccountId{static_cast<std::uint64_t>(Id)}, {}, std::move(Materials)});
            auto Published = Accounts->PrepareUpsert(Prism::Account::AccountDefinition{
                std::move(Owned), {.Quota = {.MaxConnections = 1}}});
            EXPECT_TRUE(Published);
            if (!Published) continue;
            EXPECT_TRUE(Accounts->Commit(*Published));
        }
        const auto Authority = Prism::Testing::AttachAccountAdmissionAuthority(
            Accounts->RuntimeRegistry());
        ASSERT_TRUE(Authority);
        auto View = Accounts->CompileScope(Prism::Account::CredentialScope{1U});
        ASSERT_TRUE(View);
        auto Auth = std::make_shared<Prism::DirectoryAuthenticator>(*View);
        auto Prepared = Prism::Shadowsocks2022::Prepare({"ss", Pin, {}},
            {Io.get_executor(), {Pin, *View, Auth}, {}, {}, {}});
        ASSERT_TRUE(Prepared);
        auto Bound = Prism::Shadowsocks2022::Bind(std::move(*Prepared), {});
        ASSERT_TRUE(Bound);
        auto Candidate = Prism::Composition::Recognition::CandidateFactory::MakeSs2022({7}, *Bound);
        auto Held = Auth->Authenticate({.Credential = Prism::Account::CredentialView::Psk(std::string_view(
                                            reinterpret_cast<const char*>(Key.data()), Key.size()))});
        ASSERT_TRUE(Held);
        ASSERT_TRUE(*Held);
        auto Storage = std::make_shared<const std::vector<std::byte>>(
            Prism::Testing::RecognitionWire::MakeSs2022(Key));
        auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
        auto Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
        SecondAccountEcho Probe{*Bound, Candidate.Accept, Client, Server, Accounts, Storage, Key};
        Net::co_spawn(Io, Probe.Run(Candidate.Spec, *Held),
            [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
        Io.run();
        EXPECT_TRUE(Probe.Echo);
        EXPECT_TRUE(Probe.DrainSucceeded);
    }
    TEST(ProviderAcceptPath, SsResponseWriteFailureStopsCredentialTrialsAndReleasesLease)
    {
        Net::io_context Io;
        auto Pin = Generation();
        auto Accounts = std::make_shared<Prism::Account::AccountStore>();
        const auto First = Prism::Testing::RecognitionWire::MakePsk(0x77);
        const auto Second = Prism::Testing::RecognitionWire::MakePsk(0x31);
        for (const auto& [Id, Bytes] : std::array{std::pair{1, First}, std::pair{2, Second}})
        {
            std::vector<Prism::Account::CredentialMaterial> Materials;
            Materials.push_back({Prism::Account::CredentialScope{1U}, {},
                Prism::Account::Credential::Psk(
                    std::string_view(reinterpret_cast<const char*>(Bytes.data()), Bytes.size()))});
            auto Owned = std::make_shared<const Prism::Account::AccountMaterials>(
                Prism::Account::AccountMaterials::CreateRequest{
                    Prism::AccountId{static_cast<std::uint64_t>(Id)}, {}, std::move(Materials)});
            auto Published = Accounts->PrepareUpsert(Prism::Account::AccountDefinition{
                std::move(Owned), {.MaxConnections = 1}});
            ASSERT_TRUE(Published);
            ASSERT_TRUE(Accounts->Commit(*Published));
        }
        auto View = Accounts->CompileScope(Prism::Account::CredentialScope{1U});
        ASSERT_TRUE(View);
        auto Auth = std::make_shared<Prism::DirectoryAuthenticator>(*View);
        auto Prepared = Prism::Shadowsocks2022::Prepare({"ss", Pin, {}},
            {Io.get_executor(), {Pin, *View, Auth}, {}, {}, {}});
        ASSERT_TRUE(Prepared);
        auto Bound = Prism::Shadowsocks2022::Bind(std::move(*Prepared), {});
        ASSERT_TRUE(Bound);

        auto Wire = Prism::Testing::RecognitionWire::MakeSs2022(First);
        std::vector<std::uint8_t> WireBytes;
        WireBytes.reserve(Wire.size());
        for (const auto Byte : Wire)
            WireBytes.push_back(std::to_integer<std::uint8_t>(Byte));
        auto Raw = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
        Raw->EofOnDrain = true;
        Raw->WriteErrorBytes = 1;
        Raw->SetWriteError(std::make_error_code(std::errc::connection_reset));
        Raw->InjectRead(std::move(WireBytes));

        const auto Binding = *Bound;
        Net::co_spawn(Io, RunSsResponseWriteFailure(
            {Binding, Raw, Wire.size(), Accounts}),
            [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
        Io.run();
    }
    TEST(ProviderAcceptPath, MoveAssignmentClosesOldOwnerAndMovedFromDoesNotCloseNewOwner)
    {
        Net::io_context Io;
        Prism::Socks5::ServerConfig Config;
        Config.EnableUdp = false;
        auto Owner = Prism::Testing::MakeSocks5Binding(Config);
        auto [C1, S1] = Prism::MakeMemoryPair(Io.get_executor());
        auto [C2, S2] = Prism::MakeMemoryPair(Io.get_executor());
        auto Client1 = std::make_shared<Prism::MemoryStream>(std::move(C1));
        auto Client2 = std::make_shared<Prism::MemoryStream>(std::move(C2));
        auto Server1 = std::make_shared<Prism::MemoryStream>(std::move(S1));
        auto Server2 = std::make_shared<Prism::MemoryStream>(std::move(S2));
        MovedPlaneProbe Probe{Owner, {Client1, Client2}, {Server1, Server2}};
        Net::co_spawn(Io, Probe.Run(), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
        Io.run();
    }
    TEST(ProviderAcceptPath, BoundCatalogMoveAssignmentClosesOldAliasAndDrainsItsPinOnlyAfterPlaneExit)
    {
        Net::io_context Io;
        auto OldPin = Generation();
        auto NewPin = Generation();
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> OldWeak = OldPin, NewWeak = NewPin;
        PinnedCatalogBuilder Builder{Io.get_executor()};
        auto OldCatalogResult = MakeAccountCatalog(*OldPin);
        ASSERT_TRUE(OldCatalogResult);
        auto OldCatalog = *OldCatalogResult;
        auto NewCatalogResult = MakeAccountCatalog(*NewPin);
        ASSERT_TRUE(NewCatalogResult);
        auto NewCatalog = *NewCatalogResult;
        auto Destination = Builder.Build(OldPin, "old", *OldCatalog);
        auto Incoming = Builder.Build(NewPin, "new", *NewCatalog);
        auto OldOwner = std::get<std::shared_ptr<Prism::Socks5::Binding>>(Destination.Find("old")->Owner);
        auto OldAlias = Destination.Find("old")->Stream();
        auto NewAlias = Incoming.Find("new")->Stream();
        OldPin.reset();
        NewPin.reset();
        auto [C1, S1] = Prism::MakeMemoryPair(Io.get_executor());
        auto [C2, S2] = Prism::MakeMemoryPair(Io.get_executor());
        auto [C3, S3] = Prism::MakeMemoryPair(Io.get_executor());
        auto Client1 = std::make_shared<Prism::MemoryStream>(std::move(C1));
        auto Server1 = std::make_shared<Prism::MemoryStream>(std::move(S1));
        auto Client2 = std::make_shared<Prism::MemoryStream>(std::move(C2));
        auto Server2 = std::make_shared<Prism::MemoryStream>(std::move(S2));
        auto Server3 = std::make_shared<Prism::MemoryStream>(std::move(S3));
        MovedCatalogProbe Probe{Destination, Incoming, OldOwner, OldAlias, NewAlias,
            {Client1, Client2}, {Server1, Server2, Server3}, OldWeak, NewWeak};
        Net::co_spawn(Io, Probe.Run(), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
        Io.run();
        EXPECT_TRUE(Probe.Completed);
    }
} // namespace
