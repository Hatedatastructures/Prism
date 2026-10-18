/**
 * @file GenerationPublicationAccountAdmissionTest.cpp
 * @brief generation publish、账户撤销与lease admission共用唯一CAS的回归。
 */
#include <Prism/Account/RuntimeRegistry.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>

#include <gtest/gtest.h>

#include <expected>
#include <memory>
#include <vector>

namespace
{

    class TestGeneration final : public Prism::Foundation::GenerationLifetime
    {
    public:
        explicit TestGeneration(const std::uint64_t Value) noexcept : Id_(Value) {}
        [[nodiscard]] auto Id() const noexcept -> Prism::GenerationId override { return Id_; }

    private:
        Prism::GenerationId Id_;
    };

    [[nodiscard]] auto MakeGeneration(const std::uint64_t Id)
        -> std::shared_ptr<const Prism::Foundation::GenerationLifetime>
    {
        return std::make_shared<const TestGeneration>(Id);
    }

    [[nodiscard]] auto PublishInitial(
        const std::shared_ptr<Prism::Runtime::GenerationPublication> &Publisher,
        const std::vector<Prism::AccountId> &Accounts) -> bool
    {
        auto Token = Publisher->Prepare({}, MakeGeneration(1U), Accounts);
        if (!Token)
        {
            return false;
        }
        return static_cast<bool>(Publisher->Publish(*Token));
    }

    [[nodiscard]] auto MakeRuntimeRegistry(
        const std::shared_ptr<Prism::Runtime::GenerationPublication> &Publisher)
        -> std::shared_ptr<Prism::Account::AccountRuntimeRegistry>
    {
        auto Registry = std::make_shared<Prism::Account::AccountRuntimeRegistry>();
        if (!Registry->AttachAdmissionAuthority(Publisher))
        {
            return {};
        }
        return Registry;
    }

    TEST(GenerationPublicationAccountAdmission, PublishWaitsForLeaseAdmissionCommit)
    {
        const Prism::AccountId Account{901U};
        auto Publisher = std::make_shared<Prism::Runtime::GenerationPublication>();
        ASSERT_TRUE(PublishInitial(Publisher, {Account}));
        auto Registry = MakeRuntimeRegistry(Publisher);
        ASSERT_TRUE(Registry);
        auto Runtime = Registry->FindOrCreate(Account, 1U);
        ASSERT_TRUE(Runtime);

        auto Admission = (*Runtime)->TryAcquireConnection(1U);
        ASSERT_TRUE(Admission);
        const auto BeforePublish = Publisher->Load();
        auto Token = Publisher->Prepare(Publisher->Current(), MakeGeneration(2U), {});
        ASSERT_TRUE(Token);
        const auto EarlyPublish = Publisher->Publish(*Token);
        ASSERT_FALSE(EarlyPublish);
        EXPECT_EQ(EarlyPublish.error(),
            Prism::Runtime::GenerationPublication::PublishError::AdmissionBusy);
        EXPECT_EQ(Publisher->Load(), BeforePublish);
        EXPECT_TRUE(Publisher->Load()->IsAdmitted(Account));
        EXPECT_EQ((*Runtime)->ActiveConnections(), 1U);

        Admission->Commit();
        ASSERT_TRUE(Publisher->Publish(*Token));
        EXPECT_TRUE(Publisher->Load()->IsRevoked(Account));
        const auto Rejected = (*Runtime)->TryAcquireConnection(1U);
        ASSERT_FALSE(Rejected);
        EXPECT_EQ(Rejected.error().Native,
            Prism::Account::MakeFailure(Prism::Account::FailureReason::Revoked).Native);
        (*Runtime)->ReleaseConnection();
        EXPECT_EQ((*Runtime)->ActiveConnections(), 0U);
    }

    TEST(GenerationPublicationAccountAdmission, ManualRevokeSharesPublicationGate)
    {
        const Prism::AccountId Account{902U};
        auto Publisher = std::make_shared<Prism::Runtime::GenerationPublication>();
        ASSERT_TRUE(PublishInitial(Publisher, {Account}));
        auto Registry = MakeRuntimeRegistry(Publisher);
        ASSERT_TRUE(Registry);
        auto Runtime = Registry->FindOrCreate(Account, 1U);
        ASSERT_TRUE(Runtime);
        auto Admission = (*Runtime)->TryAcquireConnection(1U);
        ASSERT_TRUE(Admission);

        const auto BusyRevoke = Registry->Revoke(Account);
        ASSERT_FALSE(BusyRevoke);
        EXPECT_EQ(BusyRevoke.error().Code, Prism::Fault::Code::WouldBlock);
        EXPECT_FALSE(Publisher->Load()->IsRevoked(Account));

        Admission->Commit();
        ASSERT_TRUE(Registry->Revoke(Account));
        EXPECT_TRUE(Publisher->Load()->IsRevoked(Account));
        const auto RevokedSnapshot = Publisher->Load();
        ASSERT_TRUE(Registry->Revoke(Account));
        EXPECT_EQ(Publisher->Load(), RevokedSnapshot);
        const auto Rejected = (*Runtime)->TryAcquireConnection(1U);
        EXPECT_FALSE(Rejected);
        (*Runtime)->ReleaseConnection();
    }

    TEST(GenerationPublicationAccountAdmission, FailedPublishCannotRestoreRevokedAccount)
    {
        const Prism::AccountId Account{903U};
        auto Publisher = std::make_shared<Prism::Runtime::GenerationPublication>();
        ASSERT_TRUE(PublishInitial(Publisher, {Account}));
        auto Registry = MakeRuntimeRegistry(Publisher);
        ASSERT_TRUE(Registry);
        auto Token = Publisher->Prepare(Publisher->Current(), MakeGeneration(2U), {});
        ASSERT_TRUE(Token);

        ASSERT_TRUE(Registry->Revoke(Account));
        const auto RevokedSnapshot = Publisher->Load();
        const auto FailedPublish = Publisher->Publish(*Token);
        ASSERT_FALSE(FailedPublish);
        EXPECT_EQ(FailedPublish.error(),
            Prism::Runtime::GenerationPublication::PublishError::StaleBase);
        const auto Current = Publisher->Load();
        EXPECT_EQ(Current, RevokedSnapshot);
        EXPECT_TRUE(Current->IsMember(Account));
        EXPECT_TRUE(Current->IsRevoked(Account));
        EXPECT_FALSE(Current->IsAdmitted(Account));
        EXPECT_EQ(Publisher->Current()->Id(), Prism::GenerationId{1U});

        const auto Readded = Publisher->Prepare(
            Publisher->Current(), MakeGeneration(2U), {Account});
        ASSERT_TRUE(Readded);
        ASSERT_TRUE(Publisher->Publish(*Readded));
        EXPECT_TRUE(Publisher->Load()->IsRevoked(Account));
        EXPECT_FALSE(Publisher->Load()->IsAdmitted(Account));
    }

} // namespace
