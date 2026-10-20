/**
 * @file RealityRecognition.cpp
 * @brief Reality 外层 ClientHello 识别回归测试。
 */

#include <gtest/gtest.h>

#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>

TEST(RealityRecognition, AllowsConfiguredRealityWithOuterEchExtension)
{
    Prism::Composition::Recognition::TlsCandidateOptions Options;
    Options.Id = 1;
    Options.Name = "vless-reality";
    Options.Scheme = "reality";
    Options.Carrier = Prism::Composition::Recognition::TlsCarrier::Reality;
    Options.ServerNames = {"example.com"};

    const auto Binding = Prism::Composition::Recognition::TlsCandidateFactory::Make(
        std::move(Options),
        [](Prism::Recognition::CarrierAcceptInput Input)
            -> boost::asio::awaitable<Prism::Recognition::CarrierAcceptResult>
        {
            Prism::Recognition::CarrierAcceptResult Result;
            Result.Transport = std::move(Input.Inbound);
            co_return Result;
        });

    Prism::Recognition::ClientHelloFeatures Features;
    Features.ServerName = "example.com";
    Features.HasX25519 = true;
    Features.HasEch = true;

    EXPECT_EQ(Binding.Inspect(Features), Prism::Recognition::MatchState::Structural);
}
