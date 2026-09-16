/**
 * @file AccountNgxTest.cpp
 * @brief 账户目录测试（T5-3 O3）
 * @details 覆盖：
 *          - CowMap：set/Find/Update/Remove/Snapshot/Clear
 *          - Directory：Upsert/Insert/Remove/Find/ForEach/Clear
 *          - Lease：RAII 释放 / move 语义 / 空判
 *          - TryAcquire：无限制 / 限制 / 禁用 / 过期 / 多协议共享配额
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <barrier>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <Preview/Account/Account.hpp>
#include <Preview/Foundation/Memory/CowMap.hpp>
#include <Preview/Foundation/Utility/Account/Directory.hpp>

namespace
{

    using Preview::Account::AccountDirectory;
    using Preview::Account::AccountRecord;
    using Preview::Account::AccountRuntimeState;
    using Preview::Account::AcquireFailure;
    using Preview::Account::Authenticator;
    using Preview::Account::AuthenticationRequest;
    using Preview::Account::Credential;
    using Preview::Account::CredentialKind;
    using Preview::Account::CredentialView;
    using Preview::Account::DirectoryAuthenticator;
    using Preview::Account::RateLimiter;
    using Preview::Account::RatePolicy;
    using Preview::Account::RateRequest;
    using Preview::Account::StrictGlobalRatePolicy;
    using Preview::Account::WorkerShardedRatePolicy;

    auto MakeRecord(AccountRecord::CreateRequest Request)
        -> std::shared_ptr<const AccountRecord>
    {
        return std::make_shared<const AccountRecord>(std::move(Request));
    }

    TEST(AccountCowMap, SetFindUpdate)
    {
        Preview::Memory::CowMap<std::string, int> m;
        m.Set("a", 1);
        m.Set("b", 2);

        int v = 0;
        EXPECT_TRUE(m.Find("a", v));
        EXPECT_EQ(v, 1);
        EXPECT_TRUE(m.Find("b", v));
        EXPECT_EQ(v, 2);
        EXPECT_FALSE(m.Find("c", v));
        EXPECT_EQ(m.Size(), 2);

        // 更新
        m.Set("a", 10);
        EXPECT_TRUE(m.Find("a", v));
        EXPECT_EQ(v, 10);
        EXPECT_EQ(m.Size(), 2);
    }

    TEST(AccountCowMap, RemoveAndClear)
    {
        Preview::Memory::CowMap<std::string, int> m;
        m.Set("a", 1);
        m.Set("b", 2);
        EXPECT_TRUE(m.Remove("a"));
        EXPECT_FALSE(m.Remove("a"));
        EXPECT_EQ(m.Size(), 1);

        m.Clear();
        EXPECT_EQ(m.Size(), 0);
        int v = 0;
        EXPECT_FALSE(m.Find("b", v));
    }

    TEST(AccountCowMap, SnapshotIsolation)
    {
        Preview::Memory::CowMap<std::string, int> m;
        m.Set("a", 1);

        auto snap1 = m.Snapshot(); // 旧快照
        m.Set("b", 2);             // 写时复制：旧快照不受影响
        EXPECT_EQ(snap1->size(), 1);
        EXPECT_EQ(m.Size(), 2);
    }

    TEST(AccountDirectory, UpsertFindRemove)
    {
        Preview::Account::Directory dir;
        EXPECT_FALSE(dir.Contains("alice"));

        dir.Upsert("alice", 5);
        EXPECT_TRUE(dir.Contains("alice"));
        auto e = dir.Find("alice");
        ASSERT_NE(e, nullptr);
        EXPECT_EQ(e->MaxConnections(), 5);
        EXPECT_FALSE(e->Disabled());

        EXPECT_TRUE(dir.Remove("alice"));
        EXPECT_FALSE(dir.Contains("alice"));
        EXPECT_EQ(dir.Size(), 0);
    }

    TEST(AccountDirectory, ForEachSnapshot)
    {
        Preview::Account::Directory dir;
        dir.Upsert("a", 1);
        dir.Upsert("b", 2);
        dir.Upsert("c", 3);

        std::vector<std::string> creds;
        dir.ForEach([&](std::string_view c, const Preview::Account::SharedEntry &)
                     { creds.emplace_back(c); });
        EXPECT_EQ(creds.size(), 3);
        EXPECT_EQ(dir.Size(), 3);

        dir.Clear();
        EXPECT_EQ(dir.Size(), 0);
    }

    TEST(AccountLease, RaiiRelease)
    {
        Preview::Account::Directory dir;
        dir.Upsert("alice", 2);

        {
            auto l1 = Preview::Account::TryAcquire(dir, "alice");
            auto l2 = Preview::Account::TryAcquire(dir, "alice");
            EXPECT_TRUE(l1);
            EXPECT_TRUE(l2);
            auto e = dir.Find("alice");
            EXPECT_EQ(e->Active(), 2);
            // 第三个被拒（超限）
            EXPECT_FALSE(Preview::Account::TryAcquire(dir, "alice"));
        } // l1/l2 析构 → 释放
        auto e = dir.Find("alice");
        EXPECT_EQ(e->Active(), 0);

        // 释放后可再获取
        EXPECT_TRUE(Preview::Account::TryAcquire(dir, "alice"));
    }

    TEST(AccountLease, MoveSemantics)
    {
        Preview::Account::Directory dir;
        dir.Upsert("bob", 1);

        auto l1 = Preview::Account::TryAcquire(dir, "bob");
        EXPECT_TRUE(l1);
        auto l2 = std::move(l1);
        EXPECT_FALSE(l1); // 移动后空
        EXPECT_TRUE(l2);
        auto e = dir.Find("bob");
        EXPECT_EQ(e->Active(), 1);
    }

    TEST(AccountLease, UnlimitedConnections)
    {
        Preview::Account::Directory dir;
        dir.Upsert("carol", 0); // 0 = 无限制

        std::vector<Preview::Account::Lease> leases;
        for (int i = 0; i < 100; ++i)
        {
            auto l = Preview::Account::TryAcquire(dir, "carol");
            ASSERT_TRUE(l);
            leases.push_back(std::move(l));
        }
        auto e = dir.Find("carol");
        EXPECT_EQ(e->Active(), 100);
    }

    TEST(AccountLease, DisabledRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("dave", {.MaxConnections = 5, .Disabled = true}); // 禁用

        EXPECT_FALSE(Preview::Account::TryAcquire(dir, "dave"));
        // 未知账户
        EXPECT_FALSE(Preview::Account::TryAcquire(dir, "nobody"));
    }

    TEST(AccountLease, ExpiredRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("eve", {.MaxConnections = 5, .ExpireAt = 1000}); // 1000ms 过期

        EXPECT_TRUE(Preview::Account::TryAcquire(dir, "eve", 500));  // 未过期
        EXPECT_FALSE(Preview::Account::TryAcquire(dir, "eve", 1000)); // 过期
        EXPECT_TRUE(Preview::Account::TryAcquire(dir, "eve", 0));     // 不校验
    }

    TEST(AccountLease, SharedEntrySharedQuota)
    {
        Preview::Account::Directory dir;
        // 两凭证共享同一 Entry → 配额共享
        auto shared = std::make_shared<Preview::Account::Entry>(1);
        dir.Insert("Tcp", shared);
        dir.Insert("udp", shared);

        EXPECT_TRUE(Preview::Account::TryAcquire(dir, "Tcp")); // 临时租约：持有一瞬
        auto l_tcp = Preview::Account::TryAcquire(dir, "Tcp");
        ASSERT_TRUE(l_tcp);
        EXPECT_FALSE(Preview::Account::TryAcquire(dir, "udp")); // 共享上限 1
        auto e = dir.Find("Tcp");
        EXPECT_EQ(e->Active(), 1);
    }

} // namespace

TEST(PreviewAccountCredential, MapsAllCredentialKinds)
{
    const auto Password = Credential::Password("password-material-17");
    const auto Uuid = Credential::Uuid(std::array<std::byte, 16>{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
        std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B}, std::byte{0x0C},
        std::byte{0x0D}, std::byte{0x0E}, std::byte{0x0F}, std::byte{0x10}});
    const auto Psk = Credential::Psk("psk-material-29");
    const auto Token = Credential::Token("token-material-41");
    const auto Extension = Credential::Extension("extension-material-53");

    EXPECT_EQ(Password.View().Kind(), CredentialKind::Password);
    EXPECT_EQ(Uuid.View().Kind(), CredentialKind::Uuid);
    EXPECT_EQ(Psk.View().Kind(), CredentialKind::Psk);
    EXPECT_EQ(Token.View().Kind(), CredentialKind::Token);
    EXPECT_EQ(Extension.View().Kind(), CredentialKind::Extension);

    EXPECT_TRUE(Password.Matches(CredentialView::Password("password-material-17")));
    EXPECT_FALSE(Password.Matches(CredentialView::Password("password-material-18")));
    EXPECT_TRUE(Psk.Matches(CredentialView::Psk("psk-material-29")));
    EXPECT_TRUE(Token.Matches(CredentialView::Token("token-material-41")));
    EXPECT_TRUE(Extension.Matches(CredentialView::Extension("extension-material-53")));
}

TEST(PreviewAccountCredential, FixedLengthComparisonRejectsLengthMismatch)
{
    const auto Psk = Credential::Psk("fixed-length");

    EXPECT_TRUE(Psk.Matches(CredentialView::Psk("fixed-length")));
    EXPECT_FALSE(Psk.Matches(CredentialView::Psk("fixed-lengt")));
    EXPECT_FALSE(Psk.Matches(CredentialView::Psk("fixed-length-extra")));
}

TEST(PreviewAccountCredential, SecretMaterialIsRedacted)
{
    const auto Secret = std::string("redaction-token-67");
    const auto Record = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{100},
        .CredentialValue = Credential::Token(Secret)});

    const auto CredentialRedacted = Record->Credential().Redacted();
    const auto RecordRedacted = Record->Redacted();
    EXPECT_EQ(CredentialRedacted, "[redacted]");
    EXPECT_EQ(CredentialRedacted.find(Secret), std::string::npos);
    EXPECT_EQ(RecordRedacted.find(Secret), std::string::npos);
    EXPECT_NE(RecordRedacted.find("100"), std::string::npos);
}

TEST(PreviewAccountDirectory, MapsCredentialKindsToRecords)
{
    const auto Uuid = std::array<std::byte, 16>{
        std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24},
        std::byte{0x25}, std::byte{0x26}, std::byte{0x27}, std::byte{0x28},
        std::byte{0x29}, std::byte{0x2A}, std::byte{0x2B}, std::byte{0x2C},
        std::byte{0x2D}, std::byte{0x2E}, std::byte{0x2F}, std::byte{0x30}};
    const auto PasswordRecord = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{101},
        .CredentialValue = Credential::Password("mapped-password-value")});
    const auto UuidRecord = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{102},
        .CredentialValue = Credential::Uuid(Uuid)});
    const auto PskRecord = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{103},
        .CredentialValue = Credential::Psk("mapped-psk-value")});
    const auto TokenRecord = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{104},
        .CredentialValue = Credential::Token("mapped-token-value")});
    const auto ExtensionRecord = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{105},
        .CredentialValue = Credential::Extension("mapped-extension-value")});

    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(PasswordRecord));
    ASSERT_TRUE(Directory.Upsert(UuidRecord));
    ASSERT_TRUE(Directory.Upsert(PskRecord));
    ASSERT_TRUE(Directory.Upsert(TokenRecord));
    ASSERT_TRUE(Directory.Upsert(ExtensionRecord));

    EXPECT_EQ(Directory.Find(CredentialView::Password("mapped-password-value"))->AccountId().Value(),
              101U);
    EXPECT_EQ(Directory.Find(CredentialView::Uuid(Uuid))->AccountId().Value(), 102U);
    EXPECT_EQ(Directory.Find(CredentialView::Psk("mapped-psk-value"))->AccountId().Value(), 103U);
    EXPECT_EQ(Directory.Find(CredentialView::Token("mapped-token-value"))->AccountId().Value(),
              104U);
    EXPECT_EQ(Directory.Find(CredentialView::Extension("mapped-extension-value"))
                  ->AccountId()
                  .Value(),
              105U);
}

TEST(PreviewAccountLease, MoveAndReleaseExactlyOnce)
{
    const auto Record = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{106},
        .CredentialValue = Credential::Password("lease-password"),
        .Quota = {.MaxConnections = 1}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Record));

    auto Result = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Record->Credential(), RateRequest{0, 1, 1}});
    ASSERT_TRUE(Result);
    static_assert(!std::is_copy_constructible_v<decltype(Result.Lease)>);
    static_assert(!std::is_copy_assignable_v<decltype(Result.Lease)>);

    auto Lease = std::move(Result.Lease);
    EXPECT_FALSE(Result.Lease);
    EXPECT_TRUE(Lease);
    EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);

    Lease.Release();
    Lease.Release();
    EXPECT_FALSE(Lease);
    EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
}

TEST(PreviewAccountLease, StreamLeaseIsMoveOnlyAndBounded)
{
    const auto Record = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{107},
        .CredentialValue = Credential::Password("stream-password"),
        .Quota = {.MaxConnections = 1, .MaxStreams = 1}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Record));

    auto Result = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Record->Credential(), RateRequest{0, 1, 1}});
    ASSERT_TRUE(Result);
    auto Account = std::move(Result.Lease);

    auto Stream = Account.TryAcquireStream();
    auto Rejected = Account.TryAcquireStream();
    static_assert(!std::is_copy_constructible_v<decltype(Stream)>);
    EXPECT_TRUE(Stream);
    EXPECT_FALSE(Rejected);

    auto MovedStream = std::move(Stream);
    EXPECT_FALSE(Stream);
    EXPECT_TRUE(MovedStream);
    MovedStream.Release();
    EXPECT_EQ(Record->Runtime()->ActiveStreams(), 0U);
}

TEST(PreviewAccountQuota, EnforcesConnectionStreamAndByteBoundaries)
{
    const auto Record = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{108},
        .CredentialValue = Credential::Password("quota-password"),
        .Quota = {.MaxConnections = 1, .MaxStreams = 1, .MaxBytes = 5}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Record));

    auto First = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Record->Credential(), RateRequest{0, 1, 1}});
    ASSERT_TRUE(First);
    auto Second = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Record->Credential(), RateRequest{0, 1, 1}});
    EXPECT_FALSE(Second);

    auto Bytes = Record->Runtime();
    EXPECT_TRUE(Bytes->TryReserveBytes(5));
    EXPECT_FALSE(Bytes->TryReserveBytes(1));
    Bytes->ReleaseBytes(2);
    EXPECT_EQ(Bytes->UsedBytes(), 3U);
    EXPECT_TRUE(Bytes->TryReserveBytes(2));
    EXPECT_FALSE(Bytes->TryReserveBytes(1));
}

TEST(PreviewAccountDirectory, RevocationRejectsNewLeaseAndPreservesExistingRelease)
{
    const auto Record = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{109},
        .CredentialValue = Credential::Token("revocable-token"),
        .Quota = {.MaxConnections = 2}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Record));

    auto Existing = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Record->Credential(), RateRequest{0, 1, 1}});
    ASSERT_TRUE(Existing);
    ASSERT_TRUE(Directory.Revoke(Preview::AccountId{109}));
    EXPECT_TRUE(Record->Runtime()->IsRevoked());

    auto Rejected = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Record->Credential(), RateRequest{0, 1, 1}});
    EXPECT_FALSE(Rejected);
    EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);

    Existing.Lease.Release();
    EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
}

TEST(PreviewAccountRate, StrictGlobalPolicyIsSharedAcrossWorkers)
{
    RateLimiter Limiter(RatePolicy{StrictGlobalRatePolicy{2, 100}});

    EXPECT_TRUE(Limiter.TryConsume(RateRequest{0, 10, 1}));
    EXPECT_TRUE(Limiter.TryConsume(RateRequest{1, 10, 1}));
    EXPECT_FALSE(Limiter.TryConsume(RateRequest{0, 10, 1}));
    EXPECT_TRUE(Limiter.TryConsume(RateRequest{0, 110, 1}));
}

TEST(PreviewAccountRate, WorkerShardedPolicyReportsBoundedOvershoot)
{
    const WorkerShardedRatePolicy Policy{2, 3, 100};
    EXPECT_EQ(Policy.PerWorkerLimit(), 2U);
    EXPECT_EQ(Policy.MaxOvershoot(), 1U);

    RateLimiter Limiter(RatePolicy{Policy});
    EXPECT_TRUE(Limiter.TryConsume(RateRequest{0, 10, 1}));
    EXPECT_TRUE(Limiter.TryConsume(RateRequest{0, 10, 1}));
    EXPECT_TRUE(Limiter.TryConsume(RateRequest{1, 10, 1}));
    EXPECT_TRUE(Limiter.TryConsume(RateRequest{1, 10, 1}));
    EXPECT_FALSE(Limiter.TryConsume(RateRequest{0, 10, 1}));
    EXPECT_FALSE(Limiter.TryConsume(RateRequest{1, 10, 1}));
}

TEST(PreviewAccountRate, RejectsZeroWorkerShardCount)
{
    RateLimiter Limiter(RatePolicy{WorkerShardedRatePolicy{0, 3, 100}});

    EXPECT_FALSE(Limiter.TryConsume(RateRequest{0, 10, 1}));
}

TEST(PreviewAccountRecord, DirectConstructionKeepsPolicyGenerationConsistent)
{
    const auto Generation = Preview::GenerationId{77};
    const auto Record = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{117},
        .CredentialValue = Credential::Password("direct-generation-account"),
        .PolicyGeneration = Generation});

    ASSERT_TRUE(Record->IsValid());
    EXPECT_EQ(Record->PolicyGeneration(), Generation);
    ASSERT_TRUE(Record->Runtime());
    EXPECT_EQ(Record->Runtime()->PolicyGeneration(), Generation);
}

TEST(PreviewAccountRate, ReconfigurationRebasesWindowAndRejectsConcurrentStaleGeneration)
{
    constexpr std::size_t StaleWorkers = 8;
    const auto Initial = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{118},
        .CredentialValue = Credential::Password("window-reconfiguration-account"),
        .Rate = StrictGlobalRatePolicy{1, 100}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Initial));

    const auto PublishedInitial = Directory.FindById(Preview::AccountId{118});
    ASSERT_TRUE(PublishedInitial);
    const auto InitialGeneration = PublishedInitial->PolicyGeneration();
    const auto InitialPolicy = PublishedInitial->Runtime()->PolicyFor(InitialGeneration);
    ASSERT_TRUE(InitialPolicy);
    auto Consumed = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{PublishedInitial->Credential(), RateRequest{0, 100, 1}});
    ASSERT_TRUE(Consumed);
    Consumed.Lease.Release();

    const auto Replacement = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{118},
        .CredentialValue = Credential::Password("window-reconfiguration-account"),
        .Rate = StrictGlobalRatePolicy{2, 1000}});
    ASSERT_TRUE(Directory.Upsert(Replacement));

    const auto PublishedReplacement = Directory.FindById(Preview::AccountId{118});
    ASSERT_TRUE(PublishedReplacement);
    const auto ReplacementGeneration = PublishedReplacement->PolicyGeneration();
    EXPECT_NE(ReplacementGeneration, InitialGeneration);
    EXPECT_EQ(PublishedReplacement->Runtime()->PolicyGeneration(), ReplacementGeneration);

    ASSERT_TRUE(PublishedReplacement->Runtime()->TryConsume(
        RateRequest{0, 200, 1}, ReplacementGeneration));

    std::atomic<std::uint32_t> StaleAccepted{0};
    std::atomic<std::uint32_t> StalePolicyAccepted{0};
    std::barrier Gate(static_cast<std::ptrdiff_t>(StaleWorkers + 1));
    std::vector<std::thread> Threads;
    Threads.reserve(StaleWorkers);
    for (std::size_t Index = 0; Index < StaleWorkers; ++Index)
    {
        Threads.emplace_back([InitialPolicy, Runtime = PublishedReplacement->Runtime(), &Gate,
                              &StaleAccepted, &StalePolicyAccepted, InitialGeneration]
                             {
                                 Gate.arrive_and_wait();
                                 if (Runtime->TryConsume(RateRequest{0, 200, 1}, InitialGeneration))
                                 {
                                     StaleAccepted.fetch_add(1, std::memory_order_relaxed);
                                 }
                                 if (InitialPolicy->TryConsume(RateRequest{0, 200, 1}))
                                 {
                                     StalePolicyAccepted.fetch_add(1, std::memory_order_relaxed);
                                 }
                                 Gate.arrive_and_wait();
                             });
    }

    Gate.arrive_and_wait();
    Gate.arrive_and_wait();
    for (auto &Thread : Threads)
    {
        Thread.join();
    }

    EXPECT_EQ(StaleAccepted.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(StalePolicyAccepted.load(std::memory_order_relaxed), 1U);
    EXPECT_TRUE(PublishedReplacement->Runtime()->TryConsume(
        RateRequest{0, 200, 1}, ReplacementGeneration));
    EXPECT_FALSE(PublishedReplacement->Runtime()->TryConsume(
        RateRequest{0, 200, 1}, ReplacementGeneration));
}

TEST(PreviewAccountRate, ReconfigurationPreservesTimestampFloorAcrossWindowReset)
{
    RateLimiter Initial(RatePolicy{StrictGlobalRatePolicy{2, 100}});
    ASSERT_TRUE(Initial.TryConsume(RateRequest{0, 1000, 1}));

    const auto Reconfigured =
        Initial.Reconfigure(RatePolicy{StrictGlobalRatePolicy{2, 1000}});
    ASSERT_TRUE(Reconfigured);

    EXPECT_FALSE(Reconfigured->TryConsume(RateRequest{0, 999, 1}));
    EXPECT_TRUE(Reconfigured->TryConsume(RateRequest{0, 1000, 1}));
}

TEST(PreviewAccountAuthenticator, CallbackReturnsMoveOnlyLease)
{
    const auto Record = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{110},
        .CredentialValue = Credential::Password("callback-password"),
        .Quota = {.MaxConnections = 1}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Record));
    DirectoryAuthenticator DirectoryCallback(&Directory);
    Authenticator AuthenticatorObject([&DirectoryCallback](const AuthenticationRequest &Request)
                                      { return DirectoryCallback.Authenticate(Request); });

    auto Result = AuthenticatorObject.Authenticate(
        AuthenticationRequest{Record->Credential(), RateRequest{0, 1, 1}});
    ASSERT_TRUE(Result.Accepted);
    EXPECT_EQ(Result.AccountId.Value(), 110U);
    EXPECT_TRUE(Result.Lease);
    Result.Lease.Release();
}

TEST(PreviewAccountCredential, RejectsUnknownEmptyAndMalformedAtConstruction)
{
    EXPECT_THROW((Credential(CredentialKind::Unknown, Preview::Account::SecureBytes{})),
                 std::invalid_argument);
    EXPECT_THROW((void)Credential::Password(""), std::invalid_argument);

    const std::array<std::byte, 1> MalformedUuid{std::byte{0x01}};
    EXPECT_THROW((Credential(CredentialKind::Uuid,
                             Preview::Account::SecureBytes(std::span<const std::byte>(MalformedUuid)))),
                 std::invalid_argument);
    EXPECT_THROW((AccountRecord(AccountRecord::CreateRequest{
                     .AccountId = Preview::AccountId{},
                     .CredentialValue = Credential::Password("valid-account-password")})),
                 std::invalid_argument);
}

TEST(PreviewAccountAuthenticator, RejectsMalformedCredentialAtAuthentication)
{
    AccountDirectory Directory;
    DirectoryAuthenticator Authenticator(&Directory);
    const auto Result = Authenticator.Authenticate(
        AuthenticationRequest{CredentialView{}, RateRequest{0, 1, 1}});

    EXPECT_FALSE(Result.Accepted);
    EXPECT_EQ(static_cast<std::uint8_t>(Result.Failure), 6U);
}

TEST(PreviewAccountDirectory, RejectsInvalidInputsAtInsertionAndAcquire)
{
    AccountDirectory Directory;

    EXPECT_FALSE(Directory.Upsert(Preview::Account::SharedAccountRecord{}));
    const auto Result = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{CredentialView{}, RateRequest{0, 1, 1}});
    EXPECT_EQ(Result.Failure, AcquireFailure::InvalidCredential);
    EXPECT_FALSE(Directory.Find(CredentialView{}));
    EXPECT_FALSE(Directory.FindById(Preview::AccountId{}));
    EXPECT_FALSE(Directory.Remove(Preview::AccountId{}));
}

TEST(PreviewAccountQuota, ReservationCannotOverrideRecordPolicy)
{
    const auto Record = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{111},
        .CredentialValue = Credential::Password("bound-quota-password"),
        .Quota = {.MaxBytes = 5}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Record));

    EXPECT_FALSE(Record->Runtime()->TryReserveBytes(6));
    EXPECT_TRUE(Record->Runtime()->TryReserveBytes(5));
    EXPECT_EQ(Record->Runtime()->UsedBytes(), 5U);
}

TEST(PreviewAccountDirectory, SameIdUpsertPreservesRuntimeAndRevocation)
{
    const auto Original = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{112},
        .CredentialValue = Credential::Password("reload-old-password"),
        .Quota = {.MaxConnections = 1}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Original));
    auto Existing = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Original->Credential(), RateRequest{0, 1, 1}});
    ASSERT_TRUE(Existing);

    const auto Replacement = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{112},
        .CredentialValue = Credential::Password("reload-new-password"),
        .Quota = {.MaxConnections = 1}});
    ASSERT_TRUE(Directory.Upsert(Replacement));
    EXPECT_EQ(Directory.FindById(Preview::AccountId{112})->Runtime(), Original->Runtime());

    auto Busy = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Replacement->Credential(), RateRequest{0, 1, 1}});
    EXPECT_FALSE(Busy);

    ASSERT_TRUE(Directory.Revoke(Preview::AccountId{112}));
    Existing.Lease.Release();
    auto Revoked = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Replacement->Credential(), RateRequest{0, 1, 1}});
    EXPECT_FALSE(Revoked);
}

TEST(PreviewAccountDirectory, SameIdUpsertPublishesPolicyGenerationWithSharedRuntime)
{
    const auto Original = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{115},
        .CredentialValue = Credential::Password("policy-generation-old"),
        .Quota = {.MaxBytes = 2},
        .Rate = StrictGlobalRatePolicy{1, 100}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Original));

    const auto PublishedOriginal = Directory.FindById(Preview::AccountId{115});
    ASSERT_TRUE(PublishedOriginal);
    EXPECT_EQ(PublishedOriginal->PolicyGeneration(), Preview::GenerationId{1});
    EXPECT_EQ(PublishedOriginal->Runtime()->PolicyGeneration(), Preview::GenerationId{1});

    auto Existing = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Original->Credential(), RateRequest{0, 100, 1}});
    ASSERT_TRUE(Existing);
    ASSERT_TRUE(PublishedOriginal->Runtime()->TryReserveBytes(2));

    const auto Replacement = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{115},
        .CredentialValue = Credential::Password("policy-generation-new"),
        .Quota = {.MaxBytes = 3},
        .Rate = StrictGlobalRatePolicy{2, 100}});
    ASSERT_TRUE(Directory.Upsert(Replacement));

    const auto PublishedReplacement = Directory.FindById(Preview::AccountId{115});
    ASSERT_TRUE(PublishedReplacement);
    EXPECT_EQ(PublishedReplacement->PolicyGeneration(), Preview::GenerationId{2});
    EXPECT_EQ(PublishedReplacement->Runtime()->PolicyGeneration(), Preview::GenerationId{2});
    EXPECT_EQ(PublishedReplacement->Runtime(), Original->Runtime());
    EXPECT_FALSE(Existing.Lease.TryReserveBytes(1));

    auto NewFirst = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Replacement->Credential(), RateRequest{0, 100, 1}});
    ASSERT_TRUE(NewFirst);
    EXPECT_TRUE(NewFirst.Lease.TryReserveBytes(1));
    EXPECT_FALSE(NewFirst.Lease.TryReserveBytes(1));
    auto NewSecond = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{Replacement->Credential(), RateRequest{0, 100, 1}});
    EXPECT_FALSE(NewSecond);

    NewFirst.Lease.ReleaseBytes(1);
    NewFirst.Lease.Release();
    Existing.Lease.Release();
}

TEST(PreviewAccountDirectory, ConcurrentReloadPublishesMatchingPolicyGenerations)
{
    constexpr std::size_t Reloads = 256;
    constexpr std::size_t Readers = 2;
    constexpr std::size_t ReadsPerReader = 1024;

    const auto Initial = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{116},
        .CredentialValue = Credential::Password("concurrent-policy-account"),
        .Quota = {.MaxBytes = 1},
        .Rate = Preview::Account::UnlimitedRatePolicy{}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(Initial));

    std::atomic<std::uint32_t> UpsertFailures{0};
    std::atomic<std::uint32_t> GenerationMismatches{0};
    std::atomic<std::uint32_t> MaxByteMismatches{0};
    std::barrier Gate(static_cast<std::ptrdiff_t>(Readers + 2));
    std::vector<std::thread> Threads;
    Threads.reserve(Readers + 1);
    Threads.emplace_back([&Directory, &Gate, &UpsertFailures]
                         {
                             Gate.arrive_and_wait();
                             for (std::size_t Index = 0; Index < Reloads; ++Index)
                             {
                                 const auto Replacement = MakeRecord(AccountRecord::CreateRequest{
                                     .AccountId = Preview::AccountId{116},
                                     .CredentialValue = Credential::Password(
                                         "concurrent-policy-account"),
                                     .Quota = {.MaxBytes = (Index % 2U) + 1U},
                                     .Rate = Preview::Account::UnlimitedRatePolicy{}});
                                 if (!Directory.Upsert(Replacement))
                                 {
                                     UpsertFailures.fetch_add(1, std::memory_order_relaxed);
                                 }
                             }
                         });

    for (std::size_t Reader = 0; Reader < Readers; ++Reader)
    {
        Threads.emplace_back([&Directory, &Gate, &GenerationMismatches, &MaxByteMismatches]
                             {
                                 Gate.arrive_and_wait();
                                 for (std::size_t Index = 0; Index < ReadsPerReader; ++Index)
                                 {
                                     auto Result = Directory.TryAcquire(
                                         AccountDirectory::AcquireRequest{
                                             CredentialView::Password("concurrent-policy-account"),
                                             RateRequest{0, 1, 1}});
                                     if (!Result)
                                     {
                                         continue;
                                     }
                                     const auto Reserved = Result.Lease.TryReserveBytes(2);
                                     if (Result.Record->PolicyGeneration() !=
                                         Result.Lease.PolicyGeneration())
                                     {
                                         GenerationMismatches.fetch_add(1,
                                                                         std::memory_order_relaxed);
                                     }
                                     if (Reserved && Result.Record->Quota().MaxBytes == 1)
                                     {
                                         MaxByteMismatches.fetch_add(1,
                                                                      std::memory_order_relaxed);
                                     }
                                     if (Reserved)
                                     {
                                         Result.Lease.ReleaseBytes(2);
                                     }
                                     Result.Lease.Release();
                                 }
                             });
    }

    Gate.arrive_and_wait();
    for (auto &Thread : Threads)
    {
        Thread.join();
    }

    EXPECT_EQ(UpsertFailures.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(GenerationMismatches.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(MaxByteMismatches.load(std::memory_order_relaxed), 0U);
}

TEST(PreviewAccountRate, RejectsDefaultAndOutOfOrderTimestamps)
{
    RateLimiter Limiter(RatePolicy{StrictGlobalRatePolicy{3, 100}});

    EXPECT_FALSE(Limiter.TryConsume(RateRequest{0, 0, 1}));
    EXPECT_TRUE(Limiter.TryConsume(RateRequest{0, 100, 1}));
    EXPECT_FALSE(Limiter.TryConsume(RateRequest{0, 99, 1}));
}

TEST(PreviewAccountRate, RejectsLimitsBeyondPackedCounterWidth)
{
    RateLimiter Limiter(
        RatePolicy{StrictGlobalRatePolicy{std::numeric_limits<std::uint64_t>::max(), 100}});

    EXPECT_FALSE(Limiter.TryConsume(RateRequest{0, 1, 1}));
}

TEST(PreviewAccountRate, RejectsWorkerShardCountBeyondBound)
{
    RateLimiter Limiter(RatePolicy{WorkerShardedRatePolicy{10000, 0, 100}});

    EXPECT_FALSE(Limiter.TryConsume(RateRequest{0, 1, 1}));
}

TEST(PreviewAccountRate, ConcurrentNewerWindowCannotBeRewoundByStaleRequests)
{
    constexpr std::size_t Rounds = 512;
    constexpr std::size_t StaleWorkers = 8;
    constexpr std::uint32_t Limit = static_cast<std::uint32_t>(StaleWorkers);

    std::vector<std::unique_ptr<RateLimiter>> Limiters;
    Limiters.reserve(Rounds);
    for (std::size_t Index = 0; Index < Rounds; ++Index)
    {
        Limiters.push_back(std::make_unique<RateLimiter>(
            RatePolicy{StrictGlobalRatePolicy{Limit, 100}}));
    }

    std::barrier Gate(static_cast<std::ptrdiff_t>(StaleWorkers + 2));
    std::vector<std::thread> Threads;
    Threads.reserve(StaleWorkers + 1);
    for (std::size_t Worker = 0; Worker < StaleWorkers; ++Worker)
    {
        Threads.emplace_back([&Limiters, &Gate]
                             {
                                 for (auto &Limiter : Limiters)
                                 {
                                     Gate.arrive_and_wait();
                                     (void)Limiter->TryConsume(RateRequest{0, 100, 1});
                                     Gate.arrive_and_wait();
                                 }
                             });
    }
    Threads.emplace_back([&Limiters, &Gate]
                         {
                             for (auto &Limiter : Limiters)
                             {
                                 Gate.arrive_and_wait();
                                 (void)Limiter->TryConsume(RateRequest{0, 200, Limit});
                                 Gate.arrive_and_wait();
                             }
                         });

    for (auto &Limiter : Limiters)
    {
        Gate.arrive_and_wait();
        Gate.arrive_and_wait();
        EXPECT_FALSE(Limiter->TryConsume(RateRequest{0, 200, 1}));
    }

    for (auto &Thread : Threads)
    {
        Thread.join();
    }
}

TEST(PreviewAccountQuota, ConcurrentReservationUsesSingleBoundedCASLedger)
{
    AccountRuntimeState Runtime(RatePolicy{Preview::Account::UnlimitedRatePolicy{}}, 100);
    std::atomic<std::uint32_t> Successes{0};
    std::vector<std::thread> Threads;
    Threads.reserve(8);
    for (std::uint32_t Index = 0; Index < 8; ++Index)
    {
        Threads.emplace_back([&Runtime, &Successes]
                             {
                                 for (std::uint32_t Attempt = 0; Attempt < 32; ++Attempt)
                                 {
                                     if (Runtime.TryReserveBytes(1))
                                     {
                                         Successes.fetch_add(1, std::memory_order_relaxed);
                                     }
                                 }
                             });
    }
    for (auto &Thread : Threads)
    {
        Thread.join();
    }

    EXPECT_EQ(Successes.load(std::memory_order_relaxed), 100U);
    EXPECT_EQ(Runtime.UsedBytes(), 100U);
    Runtime.ReleaseBytes(100);
    EXPECT_EQ(Runtime.UsedBytes(), 0U);
}

TEST(PreviewAccountLease, MoveAssignmentReleasesDestinationExactlyOnce)
{
    const auto FirstRecord = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{113},
        .CredentialValue = Credential::Password("move-assignment-first-password"),
        .Quota = {.MaxConnections = 1}});
    const auto SecondRecord = MakeRecord(AccountRecord::CreateRequest{
        .AccountId = Preview::AccountId{114},
        .CredentialValue = Credential::Password("move-assignment-second-password"),
        .Quota = {.MaxConnections = 1}});
    AccountDirectory Directory;
    ASSERT_TRUE(Directory.Upsert(FirstRecord));
    ASSERT_TRUE(Directory.Upsert(SecondRecord));

    auto First = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{FirstRecord->Credential(), RateRequest{0, 1, 1}});
    auto Second = Directory.TryAcquire(
        AccountDirectory::AcquireRequest{SecondRecord->Credential(), RateRequest{0, 1, 1}});
    ASSERT_TRUE(First);
    ASSERT_TRUE(Second);

    auto Destination = std::move(First.Lease);
    auto Source = std::move(Second.Lease);
    Destination = std::move(Source);
    EXPECT_EQ(FirstRecord->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(SecondRecord->Runtime()->ActiveConnections(), 1U);
    EXPECT_FALSE(Source);

    Destination.Release();
    Destination.Release();
    EXPECT_EQ(SecondRecord->Runtime()->ActiveConnections(), 0U);
}
