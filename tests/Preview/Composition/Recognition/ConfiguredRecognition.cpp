#include <TestSupport/Preview/ProtocolIngressBindings.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
/**
 * @file ConfiguredRecognition.cpp
 * @brief Configured 模式真实协议 wire 回归
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/ProfileBuilder.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;

    struct RecognitionRequest
    {
        Core::SharedProfile Profile;
        std::vector<std::byte> Wire;
        std::size_t Chunk{1};
        std::vector<std::byte> *Replayed{nullptr};
    };

    struct RecognitionRunRequest final
    {
        RecognitionRequest Request;
        std::shared_ptr<Preview::MemoryStream> Source;
        std::shared_ptr<Preview::MemoryStream> Inbound;
        Core::RecognizeResult &Result;
    };

    auto RunRecognitionOperation(RecognitionRunRequest Request) -> Net::awaitable<void>
    {
        for (std::size_t Offset = 0; Offset < Request.Request.Wire.size();
             Offset += Request.Request.Chunk)
        {
            const auto Size = (std::min)(Request.Request.Chunk,
                                         Request.Request.Wire.size() - Offset);
            std::error_code Error;
            co_await Request.Source->async_write_some(
                std::span<const std::byte>(Request.Request.Wire.data() + Offset, Size), Error);
            if (Error)
            {
                co_return;
            }
        }
        Request.Source->Shutdown();
        Core::Pipeline Pipeline(Request.Request.Profile);
        Request.Result = co_await Pipeline.Recognize(Request.Inbound);
        if (Request.Result.transport)
        {
            std::array<std::byte, 4096> ReplayBuffer{};
            std::error_code ReplayError;
            while (true)
            {
                const auto Count = co_await Request.Result.transport->async_read_some(
                    ReplayBuffer, ReplayError);
                if (ReplayError || Count == 0)
                {
                    break;
                }
                if (Request.Request.Replayed)
                {
                    Request.Request.Replayed->insert(
                        Request.Request.Replayed->end(), ReplayBuffer.begin(),
                        ReplayBuffer.begin() + static_cast<std::ptrdiff_t>(Count));
                }
            }
            Request.Result.transport.reset();
        }
        Request.Source->Close();
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

    auto RunRecognition(RecognitionRequest Request)
        -> Core::RecognizeResult
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        Core::RecognizeResult Result;
        const auto Scenario = RecognitionRunRequest{std::move(Request), Source, Inbound, Result};
        RunNaturalCoro(Io, RunRecognitionOperation(Scenario));
        return Result;
    }

    auto BuildConfigured(Composition::CandidateBinding Binding) -> Core::SharedProfile
    {
        Composition::ProfileBuilderOptions Options;
        Options.Mode = Core::RecognitionMode::Configured;
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding), std::move(Options));
        EXPECT_TRUE(Built.has_value());
        if (!Built)
        {
            return Core::SharedProfile{};
        }
        return Built->Profile;
    }

    TEST(ConfiguredRecognition, AcceptsStandardProtocolWiresWithExactReplay)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        const auto Psk = Preview::Testing::RecognitionWire::MakePsk(0x41);
        const std::vector<std::byte> Http = Preview::Testing::RecognitionWire::MakeHttp("payload");
        const std::vector<std::byte> Vless = Preview::Testing::RecognitionWire::MakeVless(Uuid);
        const std::vector<std::byte> Trojan = Preview::Testing::RecognitionWire::MakeTrojan("trojan-secret");
        const std::vector<std::byte> Vmess = Preview::Testing::RecognitionWire::MakeVmess(Uuid);
        const std::vector<std::byte> Ss2022 = Preview::Testing::RecognitionWire::MakeSs2022(Psk);

        const auto Cases = std::vector<std::pair<Composition::CandidateBinding, std::vector<std::byte>>>{
            {Composition::CandidateFactory::MakeHttp(Preview::Composition::Recognition::CandidateOptions{1}), Http},
            {Preview::Testing::MakeVlessCandidate(Preview::Composition::Recognition::CandidateOptions{2}, Preview::Vless::ServerConfig{Uuid}), Vless},
            {Preview::Testing::MakeTrojanCandidate(Preview::Composition::Recognition::CandidateOptions{3}, Preview::Trojan::ServerConfig{"trojan-secret"}), Trojan},
            {Preview::Testing::MakeVmessCandidate(Preview::Composition::Recognition::CandidateOptions{4}, Preview::Vmess::ServerConfig{Uuid}), Vmess},
            {Composition::CandidateFactory::MakeSs2022(
                 Composition::CandidateOptions{5}, Preview::Testing::MakeSs2022Binding(
                     Preview::Shadowsocks2022::ServerConfig{Psk, 90})), Ss2022},
        };

        std::size_t CaseIndex = 0;
        for (const auto &Entry : Cases)
        {
            auto Wire = Entry.second;
            auto Profile = BuildConfigured(Composition::CandidateBinding{Entry.first.Spec, Entry.first.Accept});
            ASSERT_NE(Profile, nullptr);
            std::vector<std::byte> Replayed;
            const auto Result = RunRecognition(RecognitionRequest{Profile, Wire, 1, &Replayed});
            EXPECT_TRUE(Result.success);
            EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
            if (!Result.success)
            {
                ADD_FAILURE() << "case=" << CaseIndex << " candidate=" << Result.Candidate
                              << " probe=" << Result.ProbeBytes << " error=" << Result.Error.message();
            }
            EXPECT_EQ(Replayed, Wire);
            ++CaseIndex;
        }
    }

    TEST(ConfiguredRecognition, RejectsWrongCredentialsAfterCompleteStructuralWire)
    {
        const auto GoodUuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        const auto WrongUuid = Preview::Testing::RecognitionWire::MakeUuid(9);
        const auto Wire = Preview::Testing::RecognitionWire::MakeVless(WrongUuid);
        auto Profile = BuildConfigured(Preview::Testing::MakeVlessCandidate(Preview::Composition::Recognition::CandidateOptions{7}, Preview::Vless::ServerConfig{GoodUuid}));
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunRecognition(RecognitionRequest{Profile, Wire, Wire.size(), nullptr});
        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Candidate, 7);
    }

    TEST(ConfiguredRecognition, RejectsTruncatedStandardWire)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        auto Wire = Preview::Testing::RecognitionWire::MakeVless(Uuid);
        Wire.resize(21);
        auto Profile = BuildConfigured(Preview::Testing::MakeVlessCandidate(Preview::Composition::Recognition::CandidateOptions{8}, Preview::Vless::ServerConfig{Uuid}));
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunRecognition(RecognitionRequest{Profile, std::move(Wire), 1, nullptr});
        EXPECT_FALSE(Result.success);
        EXPECT_TRUE(Result.Status == Core::RecognitionStatus::EndOfStream ||
                    Result.Status == Core::RecognitionStatus::NoMatch);
    }

} // namespace


