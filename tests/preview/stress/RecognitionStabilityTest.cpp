/**
 * @file RecognitionStabilityTest.cpp
 * @brief Preview 多模式识别稳定性回归
 * @details 使用真实 MemoryStream 协程覆盖顺序、并发、逐字节分片、半关、
 *          EOF、超时和输入变异；所有协程均由同一 io_context 完整驱动。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <preview/Composition/Recognition/CandidateFactory.hpp>
#include <preview/Composition/Recognition/ProfileBuilder.hpp>
#include <preview/Runtime/Recognition/Recognition.hpp>
#include <preview/Runtime/Recognition/Types.hpp>
#include <preview/Transport/MemoryStream.hpp>

#include "../core/recognition/RecognitionWire.hpp"
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;

    auto BuildProfile(Core::RecognitionMode Mode) -> Core::SharedProfile
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(17);
        std::vector<Composition::CandidateBinding> Bindings;
        Bindings.push_back(Composition::CandidateFactory::MakeHttp(1));
        if (Mode == Core::RecognitionMode::MixedTrial)
        {
            Bindings.push_back(Composition::CandidateFactory::MakeVmess(
                2, Preview::Vmess::ServerConfig{Uuid}));
        }
        Composition::ProfileBuilderOptions Options;
        Options.Mode = Mode;
        auto Built = Composition::ProfileBuilder::Build(std::move(Bindings), std::move(Options));
        if (Built)
        {
            return Built->Profile;
        }
        return Core::SharedProfile{};
    }

    auto CloseResultTransport(Core::RecognizeResult &Result) -> void
    {
        if (Result.transport)
        {
            Result.transport->Close();
            Result.transport.reset();
        }
    }

    auto RunOnce(Core::SharedProfile Profile, std::vector<std::byte> Wire, bool Fragment)
        -> Core::RecognizeResult
    {
        Net::io_context Io;
        auto [WriterValue, ReaderValue] = Preview::MakeMemoryPair(Io.get_executor());
        auto Writer = std::make_shared<Preview::MemoryStream>(std::move(WriterValue));
        auto Reader = std::make_shared<Preview::MemoryStream>(std::move(ReaderValue));
        Core::RecognizeResult Result;
        auto Run = [Writer, Reader, Profile = std::move(Profile), Wire = std::move(Wire), Fragment,
                    &Result]() mutable -> Net::awaitable<void>
        {
            std::error_code Error;
            if (Fragment)
            {
                for (std::size_t Index = 0; Index < Wire.size(); ++Index)
                {
                    const auto WriteWindow = std::span<const std::byte>(Wire).subspan(Index, 1);
                    const auto Written = co_await Writer->async_write_some(WriteWindow, Error);
                    if (Error || Written != 1)
                    {
                        co_return;
                    }
                }
            }
            else
            {
                const auto WriteWindow = std::span<const std::byte>(Wire);
                const auto Written = co_await Writer->async_write_some(WriteWindow, Error);
                if (Error || Written != Wire.size())
                {
                    co_return;
                }
            }
            Writer->Shutdown();
            Core::Pipeline Pipeline(std::move(Profile));
            Result = co_await Pipeline.Recognize(Reader);
            CloseResultTransport(Result);
            Writer->Close();
        };
        Preview::Testing::RunCoro(Io, std::move(Run));
        return Result;
    }

    auto RunTimeout(Core::SharedProfile Profile) -> Core::RecognizeResult
    {
        Net::io_context Io;
        auto [WriterValue, ReaderValue] = Preview::MakeMemoryPair(Io.get_executor());
        auto Writer = std::make_shared<Preview::MemoryStream>(std::move(WriterValue));
        auto Reader = std::make_shared<Preview::MemoryStream>(std::move(ReaderValue));
        Core::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes);
        Core::RecognitionControl Control;
        Control.Deadline = Core::RecognitionControl::Clock::now() + std::chrono::milliseconds(100);
        Core::RecognizeResult Result;
        auto Run = [Writer, Reader, Profile = std::move(Profile), &Buffer,
                    Control = std::move(Control), &Result]() mutable -> Net::awaitable<void>
        {
            Core::Pipeline Pipeline(std::move(Profile));
            Result = co_await Pipeline.Recognize(Reader, Buffer, std::move(Control));
            CloseResultTransport(Result);
            Writer->Close();
        };
        Preview::Testing::RunCoro(Io, std::move(Run));
        return Result;
    }

    struct ConcurrentState
    {
        Net::io_context *Context{nullptr};
        Core::SharedProfile Profile;
        std::vector<std::byte> Wire;
        std::vector<Core::RecognizeResult> Results;
        std::size_t Completed{0};
        std::size_t Failures{0};
    };

    auto RunConcurrentWorker(const std::shared_ptr<ConcurrentState> &State,
                             std::size_t Index) -> Net::awaitable<void>
    {
        auto [WriterValue, ReaderValue] = Preview::MakeMemoryPair(State->Context->get_executor());
        auto Writer = std::make_shared<Preview::MemoryStream>(std::move(WriterValue));
        auto Reader = std::make_shared<Preview::MemoryStream>(std::move(ReaderValue));
        std::error_code Error;
        const auto WriteWindow = std::span<const std::byte>(State->Wire);
        const auto Written = co_await Writer->async_write_some(WriteWindow, Error);
        if (Error || Written != State->Wire.size())
        {
            co_return;
        }
        Writer->Shutdown();
        Core::Pipeline Pipeline(State->Profile);
        State->Results[Index] = co_await Pipeline.Recognize(Reader);
        CloseResultTransport(State->Results[Index]);
        Writer->Close();
    }

    auto RunConcurrent(Core::SharedProfile Profile, const std::vector<std::byte> &Wire,
                       std::size_t Count) -> std::shared_ptr<ConcurrentState>
    {
        auto State = std::make_shared<ConcurrentState>();
        Net::io_context Io;
        State->Context = &Io;
        State->Profile = std::move(Profile);
        State->Wire = Wire;
        State->Results.resize(Count);
        for (std::size_t Index = 0; Index < Count; ++Index)
        {
            auto OnComplete = [State](std::exception_ptr Error) -> void
            {
                if (Error)
                {
                    ++State->Failures;
                }
                ++State->Completed;
                if (State->Completed == State->Results.size())
                {
                    State->Context->stop();
                }
            };
            Net::co_spawn(Io, RunConcurrentWorker(State, Index), std::move(OnComplete));
        }
        Io.run();
        State->Context = nullptr;
        return State;
    }

    auto IsTerminal(Core::RecognitionStatus Status) -> bool
    {
        return Status != Core::RecognitionStatus::Accepted;
    }

    TEST(RecognitionStability, SequentialRecognitionsStayDeterministic)
    {
        const auto Wire = Preview::Testing::RecognitionWire::MakeHttp("stability");
        for (const auto Mode : {Core::RecognitionMode::Configured,
                                Core::RecognitionMode::DeterministicRoute,
                                Core::RecognitionMode::MixedTrial})
        {
            auto Profile = BuildProfile(Mode);
            ASSERT_NE(Profile, nullptr);
            for (std::size_t Index = 0; Index < 1000; ++Index)
            {
                const auto Result = RunOnce(Profile, Wire, false);
                ASSERT_TRUE(Result.success) << "iteration=" << Index;
                EXPECT_EQ(Result.Candidate, 1);
                EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
            }
        }
    }

    TEST(RecognitionStability, ConcurrentRecognitionsDrainAllSessions)
    {
        const auto Wire = Preview::Testing::RecognitionWire::MakeHttp("concurrent");
        for (const auto Mode : {Core::RecognitionMode::Configured,
                                Core::RecognitionMode::DeterministicRoute,
                                Core::RecognitionMode::MixedTrial})
        {
            for (const auto Count : {std::size_t{16}, std::size_t{32}})
            {
                auto State = RunConcurrent(BuildProfile(Mode), Wire, Count);
                ASSERT_EQ(State->Failures, 0U);
                ASSERT_EQ(State->Completed, Count);
                for (const auto &Result : State->Results)
                {
                    EXPECT_TRUE(Result.success);
                    EXPECT_EQ(Result.Candidate, 1);
                    EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
                }
            }
        }
    }

    TEST(RecognitionStability, ByteFragmentationAndHalfCloseRemainBounded)
    {
        auto Profile = BuildProfile(Core::RecognitionMode::MixedTrial);
        ASSERT_NE(Profile, nullptr);
        const auto Wire = Preview::Testing::RecognitionWire::MakeHttp("fragmented");
        const auto Fragmented = RunOnce(Profile, Wire, true);
        EXPECT_TRUE(Fragmented.success);
        EXPECT_EQ(Fragmented.Candidate, 1);

        auto Truncated = Wire;
        Truncated.resize(4);
        const auto Eof = RunOnce(Profile, std::move(Truncated), true);
        EXPECT_FALSE(Eof.success);
        EXPECT_TRUE(IsTerminal(Eof.Status));
        EXPECT_EQ(Eof.transport, nullptr);
    }

    TEST(RecognitionStability, TimeoutAndMutationAreTerminal)
    {
        auto Timeout = RunTimeout(BuildProfile(Core::RecognitionMode::Configured));
        EXPECT_FALSE(Timeout.success);
        EXPECT_EQ(Timeout.Status, Core::RecognitionStatus::TimedOut);
        EXPECT_EQ(Timeout.transport, nullptr);

        const auto Wire = Preview::Testing::RecognitionWire::MakeHttp("mutation");
        auto Profile = BuildProfile(Core::RecognitionMode::MixedTrial);
        ASSERT_NE(Profile, nullptr);
        for (std::size_t Index = 0; Index < 8 && Index < Wire.size(); ++Index)
        {
            auto Mutated = Wire;
            Mutated[Index] = static_cast<std::byte>(
                static_cast<unsigned char>(Mutated[Index]) ^ static_cast<unsigned char>(0x5AU + Index));
            const auto Result = RunOnce(Profile, std::move(Mutated), false);
            EXPECT_FALSE(Result.success) << "mutation=" << Index;
            EXPECT_TRUE(IsTerminal(Result.Status));
        }

        auto Randomized = Wire;
        for (std::size_t Index = 0; Index < Randomized.size(); ++Index)
        {
            Randomized[Index] = static_cast<std::byte>((Index * 73U + 19U) & 0xFFU);
        }
        const auto RandomResult = RunOnce(Profile, std::move(Randomized), false);
        EXPECT_FALSE(RandomResult.success);
        EXPECT_TRUE(IsTerminal(RandomResult.Status));
    }

    TEST(RecognitionStability, OpaquePrefixFloodNeverCreatesWinner)
    {
        auto Profile = BuildProfile(Core::RecognitionMode::MixedTrial);
        ASSERT_NE(Profile, nullptr);
        for (std::size_t Seed = 0; Seed < 10000; ++Seed)
        {
            std::vector<std::byte> Prefix(60);
            auto Value = static_cast<std::uint32_t>(Seed + 1U);
            for (auto &Byte : Prefix)
            {
                Value = Value * 1664525U + 1013904223U;
                Byte = static_cast<std::byte>((Value >> 24) & 0xFFU);
            }
            Prefix.front() = std::byte{0xA5};
            const auto Result = RunOnce(Profile, std::move(Prefix), false);
            EXPECT_FALSE(Result.success) << "seed=" << Seed;
            EXPECT_TRUE(IsTerminal(Result.Status));
        }
    }

} // namespace
