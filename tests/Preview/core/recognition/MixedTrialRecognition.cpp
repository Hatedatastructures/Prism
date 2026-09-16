/**
 * @file MixedTrialRecognition.cpp
 * @brief MixedTrial 模式候选顺序、opaque 认证和预算回归
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <memory>
#include <vector>

#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/ProfileBuilder.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include "RecognitionWire.hpp"

namespace
{

    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;
    namespace Net = boost::asio;

    auto SnapshotOf(std::vector<std::byte> Data) -> Core::ProbeSnapshot
    {
        Core::ProbeSnapshot Snapshot;
        Snapshot.Storage = std::make_shared<const std::vector<std::byte>>(std::move(Data));
        return Snapshot;
    }

    auto RunMixed(Core::SharedProfile Profile, std::vector<std::byte> Wire) -> Core::RecognizeResult
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        Core::RecognizeResult Result;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                std::error_code Error;
                co_await Source->async_write_some(Wire, Error);
                Source->Shutdown();
                Core::Pipeline Pipeline(Profile);
                Result = co_await Pipeline.Recognize(Inbound);
                if (Result.transport)
                {
                    std::array<std::byte, 4096> ReplayBuffer{};
                    std::error_code ReplayError;
                    while (true)
                    {
                        const auto Count = co_await Result.transport->async_read_some(ReplayBuffer, ReplayError);
                        if (ReplayError || Count == 0)
                        {
                            break;
                        }
                    }
                    Result.transport.reset();
                }
                Source->Close();
            });
        return Result;
    }

    auto BuildMixed(std::vector<Composition::CandidateBinding> Bindings,
                    std::uint16_t MaxCryptoTrials = 8) -> Core::SharedProfile
    {
        Composition::ProfileBuilderOptions Options;
        Options.Mode = Core::RecognitionMode::MixedTrial;
        Options.Budget.MaxCryptoTrials = MaxCryptoTrials;
        auto Built = Composition::ProfileBuilder::Build(std::move(Bindings), std::move(Options));
        if (!Built)
        {
            ADD_FAILURE() << Core::ToStringView(Built.error());
            return {};
        }
        if (!Built)
        {
            return Core::SharedProfile{};
        }
        return Built->Profile;
    }

    TEST(MixedTrialRecognition, SelectsCleartextWinnerWithoutOpaqueLoserEffects)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        auto Profile = BuildMixed({
            Composition::CandidateFactory::MakeVless(9, Preview::Vless::ServerConfig{Uuid}),
            Composition::CandidateFactory::MakeHttp(2),
            Composition::CandidateFactory::MakeVmess(7, Preview::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunMixed(Profile, Preview::Testing::RecognitionWire::MakeHttp("tail"));
        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, 2);
        EXPECT_EQ(Result.CandidateName, "http");
        EXPECT_EQ(Result.scheme, "http");
        // 结构候选已完整确定，opaque fallback 不应被迫读取或试探。
        EXPECT_EQ(Result.CryptoTrials, 0);
    }

    TEST(MixedTrialRecognition, SameOpaqueCredentialsAreAmbiguous)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        auto Profile = BuildMixed({
            Composition::CandidateFactory::MakeVmess(
                Composition::CandidateOptions{3, "vmess-a"}, Preview::Vmess::ServerConfig{Uuid}),
            Composition::CandidateFactory::MakeVmess(
                Composition::CandidateOptions{4, "vmess-b"}, Preview::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunMixed(Profile, Preview::Testing::RecognitionWire::MakeVmess(Uuid));
        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::Ambiguous);
        EXPECT_EQ(Result.CryptoTrials, 2);
        EXPECT_EQ(Result.transport, nullptr);
    }

    TEST(MixedTrialRecognition, OpaqueTrialsRespectBudgetWithoutCommit)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        auto Profile = BuildMixed({
            Composition::CandidateFactory::MakeVmess(
                Composition::CandidateOptions{3, "vmess-a"}, Preview::Vmess::ServerConfig{Uuid}),
            Composition::CandidateFactory::MakeVmess(
                Composition::CandidateOptions{4, "vmess-b"}, Preview::Vmess::ServerConfig{Uuid}),
        }, 1);
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunMixed(Profile, Preview::Testing::RecognitionWire::MakeVmess(Uuid));
        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::BudgetExceeded);
        EXPECT_EQ(Result.CryptoTrials, 1);
        EXPECT_EQ(Result.transport, nullptr);
    }

    TEST(MixedTrialRecognition, RandomOpaquePrefixDoesNotBecomeVmessByFirstByte)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        auto Profile = BuildMixed({
            Composition::CandidateFactory::MakeVmess(3, Preview::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);
        std::vector<std::byte> Random(64);
        for (std::size_t Index = 0; Index < Random.size(); ++Index)
        {
            Random[Index] = static_cast<std::byte>((Index * 37U + 11U) & 0xFFU);
        }
        const auto Result = RunMixed(Profile, std::move(Random));
        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Candidate, Core::InvalidCandidate);
    }

    TEST(MixedTrialRecognition, WrongTrojanPasswordDoesNotFallBackToVmess)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        auto Trojan = Composition::CandidateFactory::MakeTrojan(
            3, Preview::Trojan::ServerConfig{"correct-password"});
        // 让两个 opaque 候选进入同一试探桶，确保负例验证认证而非首字节过滤。
        Trojan.Spec.FirstBytes.clear();
        Trojan.Spec.Fallback = true;
        auto Profile = BuildMixed({
            std::move(Trojan),
            Composition::CandidateFactory::MakeVmess(4, Preview::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);

        const auto Result = RunMixed(
            Profile, Preview::Testing::RecognitionWire::MakeTrojan("wrong-password"));

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Candidate, Core::InvalidCandidate);
        EXPECT_EQ(Result.transport, nullptr);
    }

    TEST(MixedTrialRecognition, OpaqueInspectOnlyChecksLengthBeforePrepare)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        auto Binding = Composition::CandidateFactory::MakeVmess(
            3, Preview::Vmess::ServerConfig{Uuid});
        std::vector<std::byte> Prefix(60, std::byte{0xA5});

        EXPECT_EQ(Binding.Spec.Inspect(SnapshotOf(std::move(Prefix))), Core::MatchState::Structural);
    }

    TEST(MixedTrialRecognition, ExpiredSs2022WireDoesNotBecomeWinner)
    {
        const auto Psk = Preview::Testing::RecognitionWire::MakePsk(0x41);
        Preview::Shadowsocks2022::ServerConfig Config;
        Config.UsePsk = true;
        Config.Psk = Psk;
        auto Profile = BuildMixed({Composition::CandidateFactory::MakeSs2022(6, Config)});
        ASSERT_NE(Profile, nullptr);
        const auto Now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        const auto Wire = Preview::Testing::RecognitionWire::MakeSs2022At(Psk, Now - 3600);
        const auto Result = RunMixed(Profile, Wire);

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Candidate, Core::InvalidCandidate);
    }

    TEST(MixedTrialRecognition, Ss2022AuthFailureFallsThroughToVmess)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        const auto Psk = Preview::Testing::RecognitionWire::MakePsk(0x51);
        Preview::Shadowsocks2022::ServerConfig SsConfig;
        SsConfig.UsePsk = true;
        SsConfig.Psk = Psk;
        auto Profile = BuildMixed({
            Composition::CandidateFactory::MakeSs2022(6, SsConfig),
            Composition::CandidateFactory::MakeVmess(7, Preview::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);

        const auto Result = RunMixed(Profile, Preview::Testing::RecognitionWire::MakeVmess(Uuid));

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, 7);
        EXPECT_EQ(Result.CryptoTrials, 2);
    }

} // namespace
