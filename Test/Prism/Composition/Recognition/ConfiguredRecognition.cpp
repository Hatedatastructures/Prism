#include <TestSupport/Prism/Protocol/Ingress.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file ConfiguredRecognition.cpp
 * @brief Configured 模式真实协议 wire 回归
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;

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
        std::shared_ptr<Prism::MemoryStream> Source;
        std::shared_ptr<Prism::MemoryStream> Inbound;
        Core::RecognizeResult &Result;
    };

    auto RunRecognitionPipeline(RecognitionRunRequest Request) -> Net::awaitable<void>
    {
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Core::Pipeline Pipeline(Request.Request.Profile, std::move(Bytes));
        Request.Result = co_await Pipeline.Recognize(Request.Inbound);
        if (!Request.Result.transport)
        {
            co_return;
        }
        std::array<std::byte, 4096> ReplayBuffer{};
        while (true)
        {
            const auto Read = co_await Request.Result.transport->ReadSome(
                std::span<std::byte>(ReplayBuffer));
            if (Read.Bytes > ReplayBuffer.size())
            {
                break;
            }
            if (Request.Request.Replayed && Read.Bytes != 0)
            {
                Request.Request.Replayed->insert(
                    Request.Request.Replayed->end(), ReplayBuffer.begin(),
                    ReplayBuffer.begin() + static_cast<std::ptrdiff_t>(Read.Bytes));
            }
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
        }
        Request.Result.transport.reset();
    }

    auto RunRecognitionOperation(Net::io_context &Io, RecognitionRunRequest Request)
        -> Net::awaitable<void>
    {
        Net::steady_timer PipelineDone(Io);
        PipelineDone.expires_after(std::chrono::seconds(10));
        std::exception_ptr PipelineFailure;
        bool PipelineExited{false};
        Net::co_spawn(Io, RunRecognitionPipeline(Request),
            [&PipelineDone, &PipelineFailure, &PipelineExited](std::exception_ptr Error)
            {
                PipelineFailure = std::move(Error);
                PipelineExited = true;
                try { (void)PipelineDone.cancel(); }
                catch (...) {}
            });
        bool WireWritten{true};
        for (std::size_t Offset = 0; Offset < Request.Request.Wire.size();
             Offset += Request.Request.Chunk)
        {
            const auto Size = (std::min)(Request.Request.Chunk,
                                         Request.Request.Wire.size() - Offset);
            std::size_t ChunkOffset = 0;
            while (ChunkOffset < Size)
            {
                const auto Remaining = Size - ChunkOffset;
                const auto Written = co_await Request.Source->WriteSome(
                    std::span<const std::byte>(
                        Request.Request.Wire.data() + Offset + ChunkOffset, Remaining));
                if (Written.Failure.Failed() || Written.Bytes == 0 ||
                    Written.Bytes > Remaining)
                {
                    WireWritten = false;
                    break;
                }
                ChunkOffset += Written.Bytes;
            }
            if (!WireWritten)
            {
                break;
            }
        }
        if (WireWritten)
        {
            WireWritten = (co_await Request.Source->WriteShutdown()).has_value();
        }
        if (!WireWritten)
        {
            (void)Request.Source->Close();
        }
        if (!PipelineExited)
        {
            boost::system::error_code WaitError;
            co_await PipelineDone.async_wait(
                Net::redirect_error(Net::use_awaitable, WaitError));
        }
        if (!PipelineExited)
        {
            ADD_FAILURE() << "configured recognition did not finish before the fixture watchdog";
            (void)Request.Source->Close();
            (void)Request.Inbound->Close();
            Io.stop();
            co_return;
        }
        if (PipelineFailure)
        {
            std::rethrow_exception(PipelineFailure);
        }
        (void)Request.Source->Close();
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
        auto [Writer, Reader] = Prism::MakeMemoryPair(Io.get_executor());
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(Reader));
        Core::RecognizeResult Result;
        const auto Scenario = RecognitionRunRequest{std::move(Request), Source, Inbound, Result};
        RunNaturalCoro(Io, RunRecognitionOperation(Io, Scenario));
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
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        const auto Psk = Prism::Testing::RecognitionWire::MakePsk(0x41);
        const std::vector<std::byte> Http = Prism::Testing::RecognitionWire::MakeHttp("payload");
        const std::vector<std::byte> Vless = Prism::Testing::RecognitionWire::MakeVless(Uuid);
        const std::vector<std::byte> Trojan = Prism::Testing::RecognitionWire::MakeTrojan("trojan-secret");
        const std::vector<std::byte> Vmess = Prism::Testing::RecognitionWire::MakeVmess(Uuid);
        const std::vector<std::byte> Ss2022 = Prism::Testing::RecognitionWire::MakeSs2022(Psk);

        const auto Cases = std::vector<std::pair<Composition::CandidateBinding, std::vector<std::byte>>>{
            {Composition::CandidateFactory::MakeHttp(
                 Prism::Composition::Recognition::CandidateOptions{1},
                 Prism::Testing::MakeHttp1Binding()), Http},
            {Prism::Testing::MakeVlessCandidate(Prism::Composition::Recognition::CandidateOptions{2}, Prism::Vless::ServerConfig{Uuid}), Vless},
            {Prism::Testing::MakeTrojanCandidate(Prism::Composition::Recognition::CandidateOptions{3}, Prism::Trojan::ServerConfig{"trojan-secret"}), Trojan},
            {Prism::Testing::MakeVmessCandidate(Prism::Composition::Recognition::CandidateOptions{4}, Prism::Vmess::ServerConfig{Uuid}), Vmess},
            {Composition::CandidateFactory::MakeSs2022(
                 Composition::CandidateOptions{5}, Prism::Testing::MakeSs2022Binding(
                     Prism::Shadowsocks2022::ServerConfig{Psk, 90})), Ss2022},
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
        const auto GoodUuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        const auto WrongUuid = Prism::Testing::RecognitionWire::MakeUuid(9);
        const auto Wire = Prism::Testing::RecognitionWire::MakeVless(WrongUuid);
        auto Profile = BuildConfigured(Prism::Testing::MakeVlessCandidate(Prism::Composition::Recognition::CandidateOptions{7}, Prism::Vless::ServerConfig{GoodUuid}));
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunRecognition(RecognitionRequest{Profile, Wire, Wire.size(), nullptr});
        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Candidate, 7);
    }

    TEST(ConfiguredRecognition, RejectsTruncatedStandardWire)
    {
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        auto Wire = Prism::Testing::RecognitionWire::MakeVless(Uuid);
        Wire.resize(21);
        auto Profile = BuildConfigured(Prism::Testing::MakeVlessCandidate(Prism::Composition::Recognition::CandidateOptions{8}, Prism::Vless::ServerConfig{Uuid}));
        ASSERT_NE(Profile, nullptr);
        const auto Result = RunRecognition(RecognitionRequest{Profile, std::move(Wire), 1, nullptr});
        EXPECT_FALSE(Result.success);
        EXPECT_TRUE(Result.Status == Core::RecognitionStatus::EndOfStream ||
                    Result.Status == Core::RecognitionStatus::NoMatch);
    }

} // namespace
