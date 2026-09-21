/**
 * @file RealityRecognition.cpp
 * @brief Reality 外层 ClientHello 识别回归测试。
 */

#include <gtest/gtest.h>

#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>

TEST(RealityRecognition, AllowsConfiguredRealityWithOuterEchExtension)
{
    Preview::Composition::Recognition::TlsCandidateOptions Options;
    Options.Id = 1;
    Options.Name = "vless-reality";
    Options.Scheme = "reality";
    Options.ServerNames = {"example.com"};

    const auto Binding = Preview::Composition::Recognition::TlsCandidateFactory::Make(
        std::move(Options), nullptr);

    Preview::Recognition::ClientHelloFeatures Features;
    Features.ServerName = "example.com";
    Features.HasX25519 = true;
    Features.HasEch = true;

    EXPECT_EQ(Binding.Inspect(Features), Preview::Recognition::MatchState::Structural);
}
