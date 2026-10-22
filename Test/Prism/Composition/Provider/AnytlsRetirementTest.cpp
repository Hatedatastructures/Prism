/** @file AnytlsRetirementTest.cpp @brief AnyTLS provider catalog 物理退役回执。 */
#include <gtest/gtest.h>
#include <Prism/Composition/Provider/BoundCatalog.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Anytls/Binding.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <boost/asio/co_spawn.hpp>
#include <exception>
#include <variant>
#include <utility>
#include "CatalogFixture.hpp"

namespace
{
    namespace P = Prism::Composition::Provider;
    namespace R = Prism::Composition::Recognition;

    TEST(AnytlsProviderRetirement, CatalogReportsOwnerRetiredAfterDrain)
    {
        ProviderTesting::Fixture Fixture;
        auto Input = Fixture.Input("anytls-instance");
        Input.Instances.front().Protocol.Name = "anytls";
        Input.Instances.front().Protocol.Builtin = "anytls";
        auto Services = Fixture.Services();
        Services.Streams.Egress = Prism::Testing::UnavailableEgress();

        auto Prepared = P::ProviderCatalog::Prepare(std::move(Input), std::move(Services));
        ASSERT_TRUE(Prepared);
        auto Frozen = Prepared->Freeze();
        ASSERT_TRUE(Frozen);
        auto Bound = Frozen->Bind({});
        ASSERT_TRUE(Bound);
        const auto* Entry = Bound->Find("anytls-instance");
        ASSERT_NE(Entry, nullptr);
        const auto Owner = std::get<std::shared_ptr<const Prism::Anytls::Binding>>(Entry->Owner);
        ASSERT_NE(Owner, nullptr);
        R::ProviderCandidateInputs CandidateInputs{*Entry, {}};
        auto Candidate = R::CandidateFactory::MakeConfiguredProvider(
            R::CandidateOptions{.Id = 1U, .Name = "anytls-instance",
                .BindingId = "anytls-instance"}, CandidateInputs);
        ASSERT_TRUE(Candidate);
        ASSERT_TRUE(Candidate->Accept);
        EXPECT_EQ(Candidate->Spec.Protocol, Prism::Contract::ProtocolType::AnyTls);

        auto Projection = Owner->BeginProjection();
        ASSERT_TRUE(Projection);
        EXPECT_EQ(Projection->Options().Configuration.Password, "provider-password");

        const auto BeforeDrain = Bound->PhysicalRetirement();
        ASSERT_EQ(BeforeDrain.Owners.size(), 1U);
        EXPECT_EQ(BeforeDrain.Owners.front().State, P::PhysicalRetirementState::Active);
        EXPECT_FALSE(BeforeDrain.Complete());

        Bound->Close();
        EXPECT_FALSE(Owner->BeginProjection());
        const auto RejectedCandidate = R::CandidateFactory::MakeConfiguredProvider(
            R::CandidateOptions{.Id = 2U, .Name = "anytls-instance",
                .BindingId = "anytls-instance"}, CandidateInputs);
        EXPECT_FALSE(RejectedCandidate);
        std::exception_ptr FirstException;
        std::expected<void, Prism::Fault::Failure> FirstDrainResult;
        boost::asio::co_spawn(Fixture.Io, Bound->Drain(),
            [&FirstException, &FirstDrainResult](std::exception_ptr Error,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                FirstException = std::move(Error);
                if (!FirstException) FirstDrainResult = std::move(Result);
            });
        Fixture.Io.run();
        ASSERT_FALSE(FirstException);
        ASSERT_FALSE(FirstDrainResult);
        EXPECT_EQ(FirstDrainResult.error().Code, Prism::Fault::Code::Blocked);
        EXPECT_FALSE(Bound->DrainFailure());
        EXPECT_FALSE(Bound->PhysicalRetirement().Complete());
        EXPECT_FALSE(Owner->IsRetired());
        EXPECT_EQ(Projection->Options().Configuration.Password, "provider-password");
        Projection.reset();

        std::exception_ptr Exception;
        std::expected<void, Prism::Fault::Failure> DrainResult;
        Fixture.Io.restart();
        boost::asio::co_spawn(Fixture.Io, Bound->Drain(),
            [&Exception, &DrainResult](std::exception_ptr Error,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                Exception = std::move(Error);
                if (!Exception) DrainResult = std::move(Result);
            });
        Fixture.Io.run();

        ASSERT_FALSE(Exception);
        ASSERT_TRUE(DrainResult);
        EXPECT_TRUE(Owner->IsRetired());
        EXPECT_FALSE(Owner->BeginProjection());
        const auto AfterDrain = Bound->PhysicalRetirement();
        ASSERT_EQ(AfterDrain.Owners.size(), 1U);
        EXPECT_EQ(AfterDrain.Owners.front().State, P::PhysicalRetirementState::Retired);
        EXPECT_TRUE(AfterDrain.Complete());
        // 派生候选由 generation 的 CandidateStore 单独拥有，可在 binding 回执后仍存活。
        EXPECT_TRUE(Candidate->Accept);
    }
}
