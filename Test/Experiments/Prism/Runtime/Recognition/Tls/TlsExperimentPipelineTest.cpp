/**
 * @file TlsExperimentPipelineTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "TlsRecognitionSupport.hpp"

#include <memory>

#include <Prism/Foundation/Memory/BytePool.hpp>

namespace
{
    /** @brief 创建 TLS 实验流水线所需的有界预读池。 */
    auto MakeExperimentProbeBytePool() -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
    }
}

TEST(TlsReassemblyTest, PipelineReassemblesCrossRecordHelloAndReplaysResidualOnce)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("pipeline.example", {"h2"}, false);
        const auto Records = MakeRecordSequence(Handshake, {4});
        const auto Following = MakeRecord(0x17, {0x7F, 0x7E});
        auto Wire = Concatenate(Records);
        Wire.insert(Wire.end(), Following.begin(), Following.end());
        Transport->Push(AsBytes(Wire));

        rec::Experiment::SniRouteTable Routes;
        Routes.Add("pipeline.example", "native", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Tls, false});
        rec::Experiment::SchemeExecutor Executor;
        auto Called = std::make_shared<bool>(false);
        Executor.RegisterScheme("native", [Called](Prism::SharedTransmission Inbound)
                                -> Net::awaitable<Prism::SharedTransmission>
        {
            *Called = true;
            co_return Inbound;
        });
        Prism::Recognition::Experiment::ProbeRecognition Pipeline(&Routes, &Executor);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_TRUE(*Called);
        ASSERT_FALSE(Result.preread.empty());
        std::vector<std::byte> Expected;
        Expected.insert(Expected.end(), Result.preread.begin(), Result.preread.end());
        const auto FollowingBytes = AsBytes(Following);
        Expected.insert(Expected.end(), FollowingBytes.begin(), FollowingBytes.end());
        std::vector<std::byte> Replayed(Expected.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });

        EXPECT_EQ(Count, Expected.size());
        EXPECT_EQ(Replayed, Expected);
    }

TEST(TlsReassemblyTest, PipelineKeepsSameRecordResidualAfterClientHello)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("same-record.example", {"h2"}, false);
        const auto Tail = MakeHandshake(0x02, {0xAA, 0xBB});
        auto Payload = Handshake;
        Payload.insert(Payload.end(), Tail.begin(), Tail.end());
        const auto Record = MakeRecord(0x16, Payload);
        Transport->Push(AsBytes(Record));

        rec::Experiment::SniRouteTable Routes;
        Routes.Add("same-record.example", "native", rec::Experiment::RouteOptions{});
        rec::Experiment::SchemeExecutor Executor;
        Executor.RegisterScheme("native", [](Prism::SharedTransmission Inbound)
                                -> Net::awaitable<Prism::SharedTransmission>
        {
            co_return Inbound;
        });
        Prism::Recognition::Experiment::ProbeRecognition Pipeline(&Routes, &Executor);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport);
                });

        EXPECT_TRUE(Result.success);
        ASSERT_FALSE(Result.preread.empty());
        EXPECT_EQ(Transport->RemainingBytes(), Tail.size());
        std::vector<std::byte> Expected;
        Expected.insert(Expected.end(), Result.preread.begin(), Result.preread.end());
        const auto TailBytes = AsBytes(Tail);
        Expected.insert(Expected.end(), TailBytes.begin(), TailBytes.end());
        std::vector<std::byte> Replayed(Expected.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });

        EXPECT_EQ(Count, Expected.size());
        EXPECT_EQ(Replayed, Expected);
    }

TEST(TlsReassemblyTest, LegacyPipelineRejectsTlsWithoutExplicitRoute)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("implicit-route.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        const auto Wire = AsBytes(Record);
        Transport->Push(Wire);

        Prism::Recognition::Experiment::ProbeRecognition Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Tls);
        ASSERT_NE(Result.transport, nullptr);
        EXPECT_EQ(Result.preread, Wire);
        std::vector<std::byte> Replayed(Wire.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });
        EXPECT_EQ(Count, Wire.size());
        EXPECT_EQ(Replayed, Wire);
    }

TEST(TlsReassemblyTest, LegacyPipelineAllowsOnlyExplicitTlsFallback)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("fallback.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        const auto Wire = AsBytes(Record);
        Transport->Push(Wire);

        rec::Experiment::SniRouteTable Routes;
        Routes.SetDefault("", Prism::Contract::ProtocolType::Tls, true);
        Prism::Recognition::Experiment::ProbeRecognition Pipeline(&Routes, nullptr);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Tls);
        EXPECT_TRUE(Result.scheme.empty());
        ASSERT_NE(Result.transport, nullptr);
        EXPECT_EQ(Result.preread, Wire);
    }

TEST(TlsReassemblyTest, PipelineUsesCallerOwnedProbeBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("caller-buffer.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));

        rec::Experiment::SniRouteTable Routes;
        Routes.Add("caller-buffer.example", "native", rec::Experiment::RouteOptions{});
        rec::Experiment::SchemeExecutor Executor;
        Executor.RegisterScheme("native", [](Prism::SharedTransmission Inbound)
                                -> Net::awaitable<Prism::SharedTransmission>
        {
            co_return Inbound;
        });
        Prism::Recognition::Experiment::ProbeRecognition Pipeline(&Routes, &Executor);
        rec::ProbeBuffer Buffer(64 * 1024, MakeExperimentProbeBytePool());
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_FALSE(Buffer.Empty());
        EXPECT_EQ(Buffer.Size(), Result.preread.size());
    }

TEST(TlsReassemblyTest, PipelineContinuesFromExistingProbeBufferWithoutDuplicateSeed)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("existing-buffer.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        const auto PrefixBytes = AsBytes(Record);
        const auto PrefixLength = std::size_t{24};
        rec::ProbeBuffer Buffer(64 * 1024, MakeExperimentProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(PrefixBytes.data(), PrefixLength)));
        Transport->Push(std::vector<std::byte>(PrefixBytes.begin() + PrefixLength, PrefixBytes.end()));

        rec::Experiment::SniRouteTable Routes;
        Routes.Add("existing-buffer.example", "native", rec::Experiment::RouteOptions{});
        rec::Experiment::SchemeExecutor Executor;
        Executor.RegisterScheme("native", [](Prism::SharedTransmission Inbound)
                                -> Net::awaitable<Prism::SharedTransmission>
        {
            co_return Inbound;
        });
        Prism::Recognition::Experiment::ProbeRecognition Pipeline(&Routes, &Executor);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Buffer.Size(), PrefixBytes.size());
        EXPECT_EQ(Result.preread, PrefixBytes);
        EXPECT_TRUE(std::equal(Buffer.Data().begin(), Buffer.Data().end(), PrefixBytes.begin(), PrefixBytes.end()));
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Tls);
    }

TEST(TlsReassemblyTest, PipelineContinuesFromPartialTlsProbeBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("partial-buffer.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        const auto Wire = AsBytes(Record);
        rec::ProbeBuffer Buffer(64 * 1024, MakeExperimentProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), 1)));
        Transport->Push(std::vector<std::byte>(Wire.begin() + 1, Wire.end()));

        rec::Experiment::SniRouteTable Routes;
        Routes.Add("partial-buffer.example", "native", rec::Experiment::RouteOptions{});
        rec::Experiment::SchemeExecutor Executor;
        Executor.RegisterScheme("native", [](Prism::SharedTransmission Inbound)
                                -> Net::awaitable<Prism::SharedTransmission>
        {
            co_return Inbound;
        });
        Prism::Recognition::Experiment::ProbeRecognition Pipeline(&Routes, &Executor);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Tls);
        EXPECT_EQ(Result.preread, Wire);
        EXPECT_EQ(Buffer.Size(), Wire.size());
    }

TEST(TlsReassemblyTest, PipelineContinuesFromPartialHttpProbeBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = AsBytes(std::vector<std::uint8_t>{'G', 'E', 'T', ' '});
        rec::ProbeBuffer Buffer(64 * 1024, MakeExperimentProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), 2)));
        Transport->Push(std::vector<std::byte>(Wire.begin() + 2, Wire.end()));
        Prism::Recognition::Experiment::ProbeRecognition Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Http);
        EXPECT_EQ(Result.preread, Wire);
        EXPECT_EQ(Buffer.Size(), Wire.size());
    }

TEST(TlsReassemblyTest, PipelineDoesNotTreatTrojanMagicAsProtocol)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = AsBytes(std::vector<std::uint8_t>{0x0D, 0x0A, 0x0D, 0x0A});
        rec::ProbeBuffer Buffer(64 * 1024, MakeExperimentProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), 1)));
        Transport->Push(std::vector<std::byte>(Wire.begin() + 1, Wire.end()));
        Prism::Recognition::Experiment::ProbeRecognition Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Unknown);
        ASSERT_EQ(Result.preread.size(), 1U);
        EXPECT_EQ(Result.preread.front(), Wire.front());
        EXPECT_EQ(Buffer.Size(), 1U);
        if (Result.transport)
        {
            Result.transport->Close();
        }
    }

TEST(TlsReassemblyTest, PipelineRejectsProtocolDetectedAfterNonEofProbeError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = AsBytes(std::vector<std::uint8_t>{'G', 'E', 'T', ' '});
        rec::ProbeBuffer Buffer(64 * 1024, MakeExperimentProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), 2)));
        Transport->Push(std::vector<std::byte>(Wire.begin() + 2, Wire.end()),
                        std::make_error_code(std::errc::connection_reset));
        Prism::Recognition::Experiment::ProbeRecognition Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.preread, Wire);
        ASSERT_NE(Result.transport, nullptr);
        std::vector<std::byte> Replayed(Wire.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });
        EXPECT_EQ(Count, Wire.size());
        EXPECT_EQ(Replayed, Wire);
    }

TEST(TlsReassemblyTest, PipelineReplaysIncompleteVlessPrefixAfterEof)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = AsBytes(std::vector<std::uint8_t>{0x00});
        rec::ProbeBuffer Buffer(64 * 1024, MakeExperimentProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), Wire.size())));
        Transport->Push({}, Prism::Fault::make_error_code(Prism::Fault::Code::Eof));
        Prism::Recognition::Experiment::ProbeRecognition Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Unknown);
        EXPECT_EQ(Result.preread, Wire);
        ASSERT_NE(Result.transport, nullptr);
        std::vector<std::byte> Replayed(Wire.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });
        EXPECT_EQ(Count, Wire.size());
        EXPECT_EQ(Replayed, Wire);
    }
