/**
 * @file CandidateHeaderContractTest.cpp
 * @brief Candidate model/helper 头文件的独立包含与选择合同测试。
 */

#include <gtest/gtest.h>

#include <utility>

#include <Preview/Composition/Recognition/CandidateFactoryHelpers.hpp>
#include <Preview/Composition/Recognition/CandidateModel.hpp>
#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Composition/Recognition/TlsCandidateModel.hpp>
#include <Preview/Composition/Recognition/TlsCarrierHelpers.hpp>
#include <Preview/Composition/Recognition/TlsRecognitionHelpers.hpp>

namespace
{

    namespace Composition = Preview::Composition::Recognition;
    namespace Core = Preview::Recognition;

} // namespace

TEST(CandidateHeaderContract, ModelKeepsCandidateIdentityAndPriority)
{
    const Composition::CandidateOptions Options{17, "edge", 9, 2, true};
    EXPECT_EQ(Options.Id, 17);
    EXPECT_EQ(Options.Name, "edge");
    EXPECT_EQ(Options.Priority, 9);
    EXPECT_EQ(Options.Tier, 2);
    EXPECT_TRUE(Options.Fallback);

    Composition::CandidateBinding Binding;
    Binding.Spec.Id = Options.Id;
    Binding.Spec.Name = Options.Name;
    Binding.Spec.Priority = Options.Priority;
    Binding.Spec.Tier = Options.Tier;
    Binding.Spec.Fallback = Options.Fallback;
    EXPECT_EQ(Binding.Spec.Id, Options.Id);
    EXPECT_EQ(Binding.Spec.Priority, Options.Priority);
    EXPECT_EQ(Binding.Spec.Tier, Options.Tier);
    EXPECT_TRUE(Binding.Spec.Fallback);
}

TEST(CandidateHeaderContract, TlsSelectionRequiresConfiguredSniAndAlpn)
{
    const auto Binding = Composition::TlsCandidateFactory::Make(
        Composition::TlsCandidateOptions{
            .Id = 18,
            .Name = "edge",
            .Scheme = "native",
            .ServerNames = {"edge.example"},
            .Alpn = {"h2"}},
        [](Preview::SharedTransmission Inbound)
            -> boost::asio::awaitable<Preview::Recognition::CarrierAcceptResult>
    {
        Preview::Recognition::CarrierAcceptResult Result;
        Result.Transport = std::move(Inbound);
        co_return Result;
    });

    Core::ClientHelloFeatures Features;
    Features.ServerName = "edge.example";
    Features.AlpnProtocols = {"http/1.1", "h2"};
    EXPECT_EQ(Binding.Inspect(Features), Core::MatchState::Structural);

    Features.ServerName = "other.example";
    EXPECT_EQ(Binding.Inspect(Features), Core::MatchState::Rejected);

    Features.ServerName = "edge.example";
    Features.AlpnProtocols = {"http/1.1"};
    EXPECT_EQ(Binding.Inspect(Features), Core::MatchState::Rejected);
}

