#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file MixedTrialRecognition.cpp
 * @brief MixedTrial 模式候选顺序、opaque 认证和预算回归
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <vector>

#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>
#include <boost/asio/co_spawn.hpp>

namespace
{

    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;
    namespace Net = boost::asio;

    auto SnapshotOf(std::vector<std::byte> Data) -> Core::ProbeSnapshot
    {
        Core::ProbeSnapshot Snapshot;
        Snapshot.Storage = std::make_shared<const std::vector<std::byte>>(std::move(Data));
        return Snapshot;
    }

    struct MixedScenarioRequest final
    {
        Net::io_context &IoContext;
        Core::SharedProfile Profile;
        std::vector<std::byte> Wire;
        Core::RecognizeResult &Result;
    };

    auto RunMixedScenario(MixedScenarioRequest Request) -> Net::awaitable<void>
    {
        auto [Writer, Reader] = Prism::MakeMemoryPair(Request.IoContext.get_executor());
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(Reader));
        std::size_t Offset = 0;
        while (Offset < Request.Wire.size())
        {
            const auto Remaining = Request.Wire.size() - Offset;
            const auto Written = co_await Source->WriteSome(
                std::span<const std::byte>(Request.Wire.data() + Offset, Remaining));
            if (Written.Failure.Failed() || Written.Bytes == 0 ||
                Written.Bytes > Remaining)
            {
                co_return;
            }
            Offset += Written.Bytes;
        }
        const auto Shutdown = co_await Source->WriteShutdown();
        if (!Shutdown)
        {
            co_return;
        }
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Core::Pipeline Pipeline(Request.Profile, std::move(Bytes));
        Request.Result = co_await Pipeline.Recognize(Inbound);
        if (Request.Result.transport)
        {
            std::array<std::byte, 4096> ReplayBuffer{};
            while (true)
            {
                const auto Read = co_await Request.Result.transport->ReadSome(
                    std::span<std::byte>(ReplayBuffer));
                if (Read.Bytes > ReplayBuffer.size() || Read.Failure.Failed() ||
                    Read.Bytes == 0)
                {
                    break;
                }
            }
            Request.Result.transport.reset();
        }
        (void)Source->Close();
    }

    auto RunNaturalCoro(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
                      [&Failure](std::exception_ptr Error) { Failure = Error; });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    auto RunMixed(Core::SharedProfile Profile, std::vector<std::byte> Wire) -> Core::RecognizeResult
    {
        Net::io_context Io;
        Core::RecognizeResult Result;
        RunNaturalCoro(Io, RunMixedScenario(
            MixedScenarioRequest{Io, std::move(Profile), std::move(Wire), Result}));
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
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        auto Profile = BuildMixed({
            Prism::Testing::MakeVlessCandidate(Prism::Composition::Recognition::CandidateOptions{9}, Prism::Vless::ServerConfig{Uuid}),
            Composition::CandidateFactory::MakeHttp(
                Prism::Composition::Recognition::CandidateOptions{2},
                Prism::Testing::MakeHttp1Binding()),
            Prism::Testing::MakeVmessCandidate(Prism::Composition::Recognition::CandidateOptions{7}, Prism::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunMixed(Profile, Prism::Testing::RecognitionWire::MakeHttp("tail"));
        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, 2);
        EXPECT_EQ(Result.CandidateName, "http");
        EXPECT_EQ(Result.scheme, "http");
        // 结构候选已完整确定，opaque fallback 不应被迫读取或试探。
        EXPECT_EQ(Result.CryptoTrials, 0);
    }

    TEST(MixedTrialRecognition, CleartextPrepareDoesNotConsumeCryptoBudgetInAnyMode)
    {
        for (const auto Mode : {Core::RecognitionMode::Configured,
                                Core::RecognitionMode::Deterministic,
                                Core::RecognitionMode::MixedTrial})
        {
            Composition::ProfileBuilderOptions Options;
            Options.Mode = Mode;
            SCOPED_TRACE(Core::ToStringView(Mode));
            if (Mode == Core::RecognitionMode::Configured) Options.ConfiguredCandidate = 2;
            Options.Budget.MaxCryptoTrials = 1;
            const auto Built = Composition::ProfileBuilder::Build(
                {Composition::CandidateFactory::MakeHttp(
                    Composition::CandidateOptions{2}, Prism::Testing::MakeHttp1Binding())},
                std::move(Options));
            ASSERT_TRUE(Built) << Core::ToStringView(Built.error());
            const auto Result = RunMixed(Built->Profile,
                Prism::Testing::RecognitionWire::MakeHttp("tail"));
            EXPECT_TRUE(Result.success);
            EXPECT_EQ(Result.Candidate, 2);
            EXPECT_EQ(Result.CryptoTrials, 0U);
        }
    }

    TEST(MixedTrialRecognition, SameOpaqueCredentialsAreAmbiguous)
    {
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        auto Profile = BuildMixed({
            Prism::Testing::MakeVmessCandidate(Composition::CandidateOptions{3, "vmess-a"}, Prism::Vmess::ServerConfig{Uuid}),
            Prism::Testing::MakeVmessCandidate(Composition::CandidateOptions{4, "vmess-b"}, Prism::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunMixed(Profile, Prism::Testing::RecognitionWire::MakeVmess(Uuid));
        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::Ambiguous);
        EXPECT_EQ(Result.CryptoTrials, 2);
        EXPECT_EQ(Result.transport, nullptr);
    }

    TEST(MixedTrialRecognition, OpaqueTrialsRespectBudgetWithoutCommit)
    {
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        auto Profile = BuildMixed({
            Prism::Testing::MakeVmessCandidate(Composition::CandidateOptions{3, "vmess-a"}, Prism::Vmess::ServerConfig{Uuid}),
            Prism::Testing::MakeVmessCandidate(Composition::CandidateOptions{4, "vmess-b"}, Prism::Vmess::ServerConfig{Uuid}),
        }, 1);
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunMixed(Profile, Prism::Testing::RecognitionWire::MakeVmess(Uuid));
        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::BudgetExceeded);
        EXPECT_EQ(Result.CryptoTrials, 1);
        EXPECT_EQ(Result.transport, nullptr);
    }

    TEST(MixedTrialRecognition, RandomOpaquePrefixDoesNotBecomeVmessByFirstByte)
    {
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        auto Profile = BuildMixed({
            Prism::Testing::MakeVmessCandidate(Prism::Composition::Recognition::CandidateOptions{3}, Prism::Vmess::ServerConfig{Uuid}),
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
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        auto Trojan = Prism::Testing::MakeTrojanCandidate(Prism::Composition::Recognition::CandidateOptions{3}, Prism::Trojan::ServerConfig{"correct-password"});
        // 让两个 opaque 候选进入同一试探桶，确保负例验证认证而非首字节过滤。
        Trojan.Spec.FirstBytes.clear();
        Trojan.Spec.Fallback = true;
        auto Profile = BuildMixed({
            std::move(Trojan),
            Prism::Testing::MakeVmessCandidate(Prism::Composition::Recognition::CandidateOptions{4}, Prism::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);

        const auto Result = RunMixed(
            Profile, Prism::Testing::RecognitionWire::MakeTrojan("wrong-password"));

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Candidate, Core::InvalidCandidate);
        EXPECT_EQ(Result.transport, nullptr);
    }

    TEST(MixedTrialRecognition, OpaqueInspectOnlyChecksLengthBeforePrepare)
    {
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        auto Binding = Prism::Testing::MakeVmessCandidate(Prism::Composition::Recognition::CandidateOptions{3}, Prism::Vmess::ServerConfig{Uuid});
        std::vector<std::byte> Prefix(60, std::byte{0xA5});

        EXPECT_EQ(Binding.Spec.Inspect(SnapshotOf(std::move(Prefix))), Core::MatchState::Structural);
    }

    TEST(MixedTrialRecognition, ExpiredSs2022WireDoesNotBecomeWinner)
    {
        const auto Psk = Prism::Testing::RecognitionWire::MakePsk(0x41);
        Prism::Shadowsocks2022::ServerConfig Config;
        Config.Psk = Psk;
        auto Profile = BuildMixed({Composition::CandidateFactory::MakeSs2022(Composition::CandidateOptions{6}, Prism::Testing::MakeSs2022Binding(Config))});
        ASSERT_NE(Profile, nullptr);
        const auto Now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        const auto Wire = Prism::Testing::RecognitionWire::MakeSs2022At(Psk, Now - 3600);
        const auto Result = RunMixed(Profile, Wire);

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Candidate, Core::InvalidCandidate);
    }

    TEST(MixedTrialRecognition, Ss2022AuthFailureFallsThroughToVmess)
    {
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        const auto Psk = Prism::Testing::RecognitionWire::MakePsk(0x51);
        Prism::Shadowsocks2022::ServerConfig SsConfig;
        SsConfig.Psk = Psk;
        auto Profile = BuildMixed({
            Composition::CandidateFactory::MakeSs2022(Composition::CandidateOptions{6}, Prism::Testing::MakeSs2022Binding(SsConfig)),
            Prism::Testing::MakeVmessCandidate(Prism::Composition::Recognition::CandidateOptions{7}, Prism::Vmess::ServerConfig{Uuid}),
        });
        ASSERT_NE(Profile, nullptr);

        const auto Result = RunMixed(Profile, Prism::Testing::RecognitionWire::MakeVmess(Uuid));

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, 7);
        EXPECT_EQ(Result.CryptoTrials, 2);
    }

} // namespace
